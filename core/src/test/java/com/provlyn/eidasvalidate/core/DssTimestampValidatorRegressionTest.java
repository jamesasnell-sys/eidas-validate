package com.provlyn.eidasvalidate.core;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Regression cover for three defects that all failed the same way: they
 * produced a plausible indeterminate answer rather than an error, so nothing
 * looked broken and every check silently declined to run.
 *
 * <p>These use a real RFC 3161 token, issued by a throwaway authority created
 * for the purpose, rather than a synthetic structure. The point of each test is
 * that a check which can be performed is performed. A validator that reports
 * indeterminate for everything passes no test here, which is the property that
 * was missing when the defects went unnoticed.
 *
 * <p>No network. Trusted list data is absent throughout, so trust remains
 * unknown; that is deliberate and separate from whether the token checks ran.
 */
class DssTimestampValidatorRegressionTest {

    @TempDir
    File cacheDirectory;

    private DssTimestampValidator validator() {
        return new DssTimestampValidator(
                new TrustedListManager(cacheDirectory, Duration.ofHours(12)), List.of());
    }

    private static byte[] fixture(String name) throws IOException {
        try (InputStream in =
                DssTimestampValidatorRegressionTest.class.getResourceAsStream("/fixtures/" + name)) {
            assertNotNull(in, "missing fixture: " + name);
            return in.readAllBytes();
        }
    }

    private static byte[] sha256(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    /**
     * The certificate verifier was set after the token was parsed rather than
     * before it. DSS requires one to exist at parse time, so every token,
     * genuine or otherwise, came back reported as unparseable bytes.
     */
    @Test
    @DisplayName("a real token parses, rather than being reported unparseable")
    void realTokenParses() throws Exception {
        TimestampValidationResult r = validator().validate(fixture("genuine-token.der"));

        assertNotNull(r.genTime(), "a parsed token carries a generation time");
        assertEquals(Outcome.VALID, r.token().signature(),
                "the token is correctly signed and the signature check must say so");
        assertNotNull(r.token().issuerDn(), "the issuer should have been read from the token");
    }

    /**
     * matchData was never called, so the flags reporting whether the imprint
     * was found and intact kept their defaults and a genuine match read as
     * INVALID.
     */
    @Test
    @DisplayName("digest matching the token reports the imprint valid")
    void imprintMatches() throws Exception {
        byte[] digest = sha256(fixture("document.txt"));

        TimestampValidationResult r =
                validator().validateDigest(fixture("genuine-token.der"), digest, "SHA-256");

        assertEquals(Outcome.VALID, r.token().messageImprint(),
                "this digest is the one the token attests to");
    }

    /**
     * A .tsr file, and the tokens embedded in a certificate PDF, are a full
     * RFC 3161 TimeStampResp: the response with its PKIStatusInfo wrapper, not
     * the bare TimeStampToken. This is the format timestamp authorities actually
     * hand out, so the validator must accept it — an earlier version parsed only
     * the bare token and reported a real .tsr as unparseable bytes.
     */
    @Test
    @DisplayName("a full TimeStampResp (.tsr) is unwrapped and validated, not rejected")
    void fullResponseIsUnwrapped() throws Exception {
        TimestampValidationResult r = validator().validate(fixture("genuine-response.tsr"));

        assertNotNull(r.genTime(), "a .tsr carries a generation time once unwrapped");
        assertEquals(Outcome.VALID, r.token().signature(),
                "the response wraps a correctly-signed token and must report its signature valid");
        assertNotNull(r.token().issuerDn(), "the issuer is read from the unwrapped token");
    }

    /**
     * The same document, checked against the .tsr rather than the bare token,
     * must still match. Unwrapping must not disturb the message imprint.
     */
    @Test
    @DisplayName("digest matching a .tsr response reports the imprint valid")
    void fullResponseImprintMatches() throws Exception {
        byte[] digest = sha256(fixture("response-document.txt"));

        TimestampValidationResult r =
                validator().validateDigest(fixture("genuine-response.tsr"), digest, "SHA-256");

        assertEquals(Outcome.VALID, r.token().messageImprint(),
                "the imprint check must run on the unwrapped token");
    }

    /**
     * The counterpart to the above. A validator that answers VALID to
     * everything would pass the previous test; this one is what makes the
     * imprint check mean something.
     */
    @Test
    @DisplayName("digest of an altered document reports the imprint invalid")
    void alteredDocumentIsCaught() throws Exception {
        byte[] digest = sha256(fixture("document-altered.txt"));

        TimestampValidationResult r =
                validator().validateDigest(fixture("genuine-token.der"), digest, "SHA-256");

        assertEquals(Outcome.INVALID, r.token().messageImprint(),
                "the document differs from the one timestamped and must be reported as such");
        assertEquals(Outcome.VALID, r.token().signature(),
                "the token itself is untouched; only the document differs");
    }

    /**
     * Algorithm names were passed to DSS unnormalised. DSS names its constants
     * without separators, so the ordinary spelling threw, was swallowed, and
     * pushed the request onto the no-document path. The digest route is the
     * primary API, so this silently disabled the main feature.
     */
    @Test
    @DisplayName("everyday spellings of the algorithm name are accepted")
    void algorithmNameSpellings() throws Exception {
        byte[] digest = sha256(fixture("document.txt"));

        for (String spelling : List.of("SHA-256", "sha-256", "SHA256", "sha256", " SHA-256 ")) {
            TimestampValidationResult r =
                    validator().validateDigest(fixture("genuine-token.der"), digest, spelling);

            assertEquals(Outcome.VALID, r.token().messageImprint(),
                    "spelling \"" + spelling + "\" should resolve to the same algorithm");
        }
    }

    @Test
    @DisplayName("an unrecognised algorithm name does not become a failed match")
    void unknownAlgorithmIsNotAFailedMatch() throws Exception {
        byte[] digest = sha256(fixture("document.txt"));

        TimestampValidationResult r =
                validator().validateDigest(fixture("genuine-token.der"), digest, "SHA-999");

        assertNotEquals(Outcome.INVALID, r.token().messageImprint(),
                "an unknown algorithm means the check could not run, not that the document differs");
    }

    /**
     * The token here is signed by an authority that is not in any trusted list
     * and never will be. Its signature is mathematically sound, which is the
     * point: signature validity establishes that the token was not altered
     * after signing, and says nothing about who was entitled to sign it.
     */
    @Test
    @DisplayName("a token from an unrecognised authority is never reported qualified")
    void forgedTokenIsNotQualified() throws Exception {
        TimestampValidationResult r = validator().validate(fixture("forged-token.der"));

        assertNotEquals(TrustLevel.QUALIFIED, r.trust().level(),
                "an authority absent from the trusted lists cannot be qualified");
        assertEquals(TrustLevel.UNKNOWN, r.trust().level());
        assertNotEquals(Outcome.VALID, r.trust().determination(),
                "trust must not be affirmed on the strength of a self-issued signature");
    }

    @Test
    @DisplayName("truncated DER is refused without an exception escaping")
    void truncatedTokenIsRefused() throws Exception {
        TimestampValidationResult r = validator().validate(fixture("truncated-token.der"));

        assertEquals(Outcome.INDETERMINATE, r.trust().determination());
        assertEquals(TrustLevel.UNKNOWN, r.trust().level());
        assertTrue(r.notes().stream().anyMatch(n -> !n.isBlank()),
                "a refusal must carry a reason");
    }

    /**
     * A public endpoint parsing attacker-supplied DER must fail predictably on
     * anything malformed. None of these should throw, and none should produce
     * a positive finding.
     */
    @Test
    @DisplayName("malformed input yields indeterminate rather than throwing")
    void malformedInputCorpus() {
        List<byte[]> corpus = List.of(
                new byte[] {0x30},
                new byte[] {0x30, (byte) 0x82, (byte) 0xFF, (byte) 0xFF},
                new byte[] {0x00, 0x00, 0x00, 0x00},
                new byte[] {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF},
                new byte[64],
                "<?xml version=\"1.0\"?><x/>".getBytes());

        for (byte[] input : corpus) {
            TimestampValidationResult r = validator().validate(input);

            assertEquals(Outcome.INDETERMINATE, r.trust().determination(),
                    "malformed input must not yield a determination");
            assertNotEquals(TrustLevel.QUALIFIED, r.trust().level());
        }
    }
}
