package com.provlyn.eidasvalidate.core;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.TimestampQualification;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.tsl.TLInfo;
import eu.europa.esig.dss.model.tsl.TrustProperties;
import eu.europa.esig.dss.model.tsl.TrustServiceStatusAndInformationExtensions;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.timestamp.DetachedTimestampValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Objects;

/**
 * Validates RFC 3161 timestamp tokens using the European Commission's DSS
 * library.
 *
 * <p>The qualification determination is DSS's own. This class supplies inputs,
 * sets the assessment time, and translates the output. It does not reimplement
 * the ETSI rules on top of DSS's parser, because the argument for using the
 * Commission's library only holds if the Commission's library made the
 * determination.
 *
 * <p>Both directions of error are serious. A token wrongly reported as not
 * qualified undermines the holder of a sound one; a token wrongly reported as
 * qualified conceals a defect that nothing else would catch. Neither is a
 * fallback for the other, and every point at which a determination cannot be
 * made yields INDETERMINATE carrying the reason it could not.
 */
public class DssTimestampValidator implements TimestampValidator {

    private static final Logger log = LoggerFactory.getLogger(DssTimestampValidator.class);

    private final TrustedListManager trustedLists;
    private final List<PinnedAnchor> pinnedAnchors;

    public DssTimestampValidator(TrustedListManager trustedLists, List<PinnedAnchor> pinnedAnchors) {
        this.trustedLists = Objects.requireNonNull(trustedLists, "trustedLists");
        this.pinnedAnchors = List.copyOf(Objects.requireNonNull(pinnedAnchors, "pinnedAnchors"));
    }

    @Override
    public TimestampValidationResult validate(byte[] token) {
        return run(token, (DSSDocument) null, null);
    }

    @Override
    public TimestampValidationResult validate(byte[] token, byte[] document) {
        return run(token, document == null ? null : new InMemoryDocument(document), null);
    }

    @Override
    public TimestampValidationResult validateDigest(byte[] token, byte[] digest, String digestAlgorithm) {
        return run(token, digestDocument(digest, digestAlgorithm), null);
    }

    /**
     * Build a digest document, or null where the digest cannot be used. A digest
     * that does not match the algorithm the token names is not a failed match,
     * it is a check that could not be performed, and must not be reported as one.
     */
    private DSSDocument digestDocument(byte[] digest, String digestAlgorithm) {
        if (digest == null || digest.length == 0 || digestAlgorithm == null) {
            return null;
        }
        try {
            DigestAlgorithm algorithm = parseDigestAlgorithm(digestAlgorithm);
            if (algorithm == null) {
                log.debug("Unrecognised digest algorithm: {}", digestAlgorithm);
                return null;
            }
            int expectedBytes = digestBytes(algorithm);
            if (expectedBytes < 0 || digest.length != expectedBytes) {
                return null;
            }
            return new DigestDocument(algorithm, digest);
        } catch (Exception e) {
            log.debug("Unrecognised digest algorithm: {}", digestAlgorithm);
            return null;
        }
    }

    /**
     * Resolve an algorithm name to a DSS {@link DigestAlgorithm}, accepting the
     * everyday spellings callers actually send.
     *
     * <p>DSS names its constants without separators (SHA256, SHA3-256's constant
     * is SHA3_256), but a browser or a person will send "SHA-256", "sha256", or
     * "SHA-3-256". DSS's own {@code forName} rejects the hyphenated forms, which
     * would silently push a well-formed digest request onto the "no document"
     * path and report it INDETERMINATE. Normalising here is the difference
     * between the digest path working and appearing to do nothing.
     */
    private static DigestAlgorithm parseDigestAlgorithm(String name) {
        String cleaned = name.trim().toUpperCase().replace("-", "").replace("_", "").replace(" ", "");
        return switch (cleaned) {
            case "SHA1" -> DigestAlgorithm.SHA1;
            case "SHA224" -> DigestAlgorithm.SHA224;
            case "SHA256" -> DigestAlgorithm.SHA256;
            case "SHA384" -> DigestAlgorithm.SHA384;
            case "SHA512" -> DigestAlgorithm.SHA512;
            case "SHA3224" -> DigestAlgorithm.SHA3_224;
            case "SHA3256" -> DigestAlgorithm.SHA3_256;
            case "SHA3384" -> DigestAlgorithm.SHA3_384;
            case "SHA3512" -> DigestAlgorithm.SHA3_512;
            default -> null;
        };
    }

    /** Digest length in bytes, or -1 where the algorithm has no fixed length. */
    private static int digestBytes(DigestAlgorithm algorithm) {
        return switch (algorithm) {
            case SHA1 -> 20;
            case SHA224, SHA3_224 -> 28;
            case SHA256, SHA3_256 -> 32;
            case SHA384, SHA3_384 -> 48;
            case SHA512, SHA3_512 -> 64;
            default -> -1;
        };
    }

    @Override
    public TimestampValidationResult validateAsAt(byte[] token, byte[] document, Instant assessmentTime) {
        return run(token, document == null ? null : new InMemoryDocument(document), assessmentTime);
    }

    private TimestampValidationResult run(byte[] token, DSSDocument document, Instant assessmentOverride) {
        List<String> notes = new ArrayList<>();

        if (token == null || token.length == 0) {
            return unableToDetermine(null, notes, "No timestamp token supplied.");
        }

        // DSS's DetachedTimestampValidator requires a CertificateVerifier to be
        // set before the token can be parsed at all, even though parsing itself
        // establishes no trust. An empty verifier is enough to get past the
        // parse; the trusted certificate source is attached below, only once we
        // know list data is loaded and are about to run the full validation.
        DetachedTimestampValidator validator;
        TimestampToken parsed;
        CommonCertificateVerifier verifier = new CommonCertificateVerifier();
        try {
            DSSDocument tokenDocument = new InMemoryDocument(token);
            validator = new DetachedTimestampValidator(tokenDocument);
            validator.setCertificateVerifier(verifier);
            parsed = validator.getTimestamp();
        } catch (Exception e) {
            log.debug("Token could not be parsed", e);
            return unableToDetermine(null, notes,
                    "The supplied bytes could not be parsed as an RFC 3161 timestamp token.");
        }

        Instant genTime = parsed.getGenerationTime() == null
                ? null
                : parsed.getGenerationTime().toInstant();

        if (genTime == null) {
            notes.add("The token asserts no generation time, so trust status cannot be "
                    + "assessed at the moment of stamping.");
            return unableToDetermine(null, notes,
                    "Token carries no generation time.");
        }

        // The assessment time is the moment of stamping, never the present.
        // A service withdrawn after issuance does not retroactively unqualify
        // the tokens it issued while granted, and a service granted after
        // issuance does not retroactively qualify them.
        Instant assessmentTime = assessmentOverride != null ? assessmentOverride : genTime;

        // DSS populates isMessageImprintDataFound / isMessageImprintDataIntact
        // on the token only when matchData is called against the timestamped
        // content. setTimestampedData alone does not trigger it, so tokenCheck
        // would otherwise read stale defaults and report a genuine match as
        // INVALID. This is the check that answers "does this token attest to
        // this document"; it must run whenever a document or digest is present.
        boolean imprintChecked = false;
        if (document != null) {
            validator.setTimestampedData(document);
            try {
                parsed.matchData(document);
                imprintChecked = true;
            } catch (Exception e) {
                log.debug("Message imprint match could not be performed", e);
            }
        }

        // Signature intactness and message-imprint matching are properties of
        // the token and the document alone. They do not depend on trusted list
        // data, so validateDocument runs whether or not lists are loaded — DSS
        // populates those checks during it, and skipping it (as an earlier
        // version did when lists were absent) left a genuine token reporting
        // its own signature INVALID. When lists are loaded, the trusted source
        // is attached first so the same pass can also reach a trust verdict.
        boolean listsLoaded = trustedLists.isLoaded();
        if (listsLoaded) {
            verifier.setTrustedCertSources(trustedLists.certificateSource());
        } else {
            notes.add("No trusted list data is loaded, so no qualification determination "
                    + "was attempted. The token's own signature and message imprint are "
                    + "still checked.");
        }
        validator.setValidationTime(Date.from(assessmentTime));

        Reports reports;
        try {
            reports = validator.validateDocument();
        } catch (Exception e) {
            log.debug("DSS validation failed", e);
            notes.add("The validation process did not complete.");
            return new TimestampValidationResult(
                    genTime,
                    tokenCheck(parsed, imprintChecked),
                    new TimestampValidationResult.TrustAssessment(
                            TrustLevel.UNKNOWN, Outcome.INDETERMINATE, null, null),
                    trustedLists.cacheStatus(null),
                    List.copyOf(notes));
        }

        if (!listsLoaded) {
            // Signature and imprint have now been evaluated; trust has not,
            // because there was nothing to anchor it to. Report the token
            // checks honestly and leave trust unknown.
            return new TimestampValidationResult(
                    genTime,
                    tokenCheck(parsed, imprintChecked),
                    new TimestampValidationResult.TrustAssessment(
                            TrustLevel.UNKNOWN, Outcome.INDETERMINATE, null, null),
                    trustedLists.cacheStatus(null),
                    List.copyOf(notes));
        }

        return assemble(parsed, reports, imprintChecked, assessmentTime, genTime, notes);
    }

    private TimestampValidationResult assemble(
            TimestampToken parsed,
            Reports reports,
            boolean documentSupplied,
            Instant assessmentTime,
            Instant genTime,
            List<String> notes) {

        SimpleReport simple = reports.getSimpleReport();
        String timestampId = simple.getFirstTimestampId();

        TimestampValidationResult.TrustAssessment trust =
                assessTrust(parsed, simple, timestampId, assessmentTime, notes);

        String territory = trust.trustedList() == null ? null : trust.trustedList().countryCode();

        if (timestampId != null) {
            Indication indication = simple.getIndication(timestampId);
            if (indication == Indication.INDETERMINATE) {
                notes.add("The validation process returned indeterminate: "
                        + simple.getSubIndication(timestampId) + ".");
            }
        }

        return new TimestampValidationResult(
                genTime,
                tokenCheck(parsed, documentSupplied),
                trust,
                trustedLists.cacheStatus(territory),
                List.copyOf(notes));
    }

    /**
     * Structural validity of the token. Nothing here establishes trust: an
     * attacker running their own authority produces a token that passes every
     * check in this method.
     */
    private TimestampValidationResult.TokenCheck tokenCheck(TimestampToken parsed, boolean documentSupplied) {
        Outcome signature = toOutcome(safely(parsed::isSignatureIntact));

        Outcome imprint = documentSupplied
                ? toOutcome(safely(parsed::isMessageImprintDataFound)
                        && safely(parsed::isMessageImprintDataIntact))
                : Outcome.INDETERMINATE;

        CertificateToken signing = signingCertificate(parsed);

        Outcome certificateValidity = Outcome.INDETERMINATE;
        String issuerDn = null;
        String fingerprint = null;

        if (signing != null) {
            issuerDn = signing.getIssuer() == null ? null : signing.getIssuer().getCanonical();
            fingerprint = sha256Hex(signing);
            if (parsed.getGenerationTime() != null) {
                // Validity is judged at the moment of stamping. A certificate
                // that has since expired did not invalidate the tokens it
                // signed while it was current.
                certificateValidity = toOutcome(signing.isValidOn(parsed.getGenerationTime()));
            }
        }

        String digestAlgorithm = parsed.getMessageImprint() == null
                || parsed.getMessageImprint().getAlgorithm() == null
                        ? null
                        : parsed.getMessageImprint().getAlgorithm().getName();

        return new TimestampValidationResult.TokenCheck(
                signature, imprint, certificateValidity, digestAlgorithm, issuerDn, fingerprint);
    }

    /**
     * What the issuing authority is. Established from the trusted lists where
     * possible, from the pinned anchor set otherwise, and left UNKNOWN rather
     * than guessed.
     */
    private TimestampValidationResult.TrustAssessment assessTrust(
            TimestampToken parsed,
            SimpleReport simple,
            String timestampId,
            Instant assessmentTime,
            List<String> notes) {

        if (timestampId == null) {
            notes.add("The validation report contained no timestamp entry.");
            return new TimestampValidationResult.TrustAssessment(
                    TrustLevel.UNKNOWN, Outcome.INDETERMINATE, null, null);
        }

        TimestampQualification qualification = simple.getTimestampQualification(timestampId);

        if (qualification == TimestampQualification.QTSA) {
            TimestampValidationResult.TrustedListEvidence evidence =
                    trustedListEvidence(parsed, assessmentTime, notes);
            if (evidence == null) {
                // DSS says qualified but we cannot produce the evidence for it.
                // Reporting qualified without being able to show why is not a
                // position this service takes.
                notes.add("A qualified determination was reached but the supporting "
                        + "trusted list entry could not be identified.");
                return new TimestampValidationResult.TrustAssessment(
                        TrustLevel.UNKNOWN, Outcome.INDETERMINATE, null, null);
            }
            return new TimestampValidationResult.TrustAssessment(
                    TrustLevel.QUALIFIED, Outcome.VALID, evidence, null);
        }

        PinnedAnchor pinned = matchPinnedAnchor(parsed);
        if (pinned != null) {
            return new TimestampValidationResult.TrustAssessment(
                    TrustLevel.RECOGNISED,
                    Outcome.VALID,
                    null,
                    new TimestampValidationResult.PinnedAnchorEvidence(
                            pinned.name(), pinned.certificateSha256()));
        }

        if (qualification == TimestampQualification.TSA) {
            notes.add("The issuing service appears in a trusted list but not as a "
                    + "qualified timestamping service at the time of stamping.");
            TimestampValidationResult.TrustedListEvidence evidence =
                    trustedListEvidence(parsed, assessmentTime, notes);
            return new TimestampValidationResult.TrustAssessment(
                    TrustLevel.RECOGNISED, Outcome.VALID, evidence, null);
        }

        notes.add("The issuing authority could not be placed in an EU trusted list "
                + "or in the recognised anchor set. This is not evidence of forgery.");
        return new TimestampValidationResult.TrustAssessment(
                TrustLevel.UNKNOWN, Outcome.INDETERMINATE, null, null);
    }

    private TimestampValidationResult.TrustedListEvidence trustedListEvidence(
            TimestampToken parsed, Instant assessmentTime, List<String> notes) {

        CertificateToken signing = signingCertificate(parsed);
        if (signing == null) {
            return null;
        }

        List<TrustProperties> properties = trustedLists.certificateSource().getTrustServices(signing);
        if (properties == null || properties.isEmpty()) {
            return null;
        }

        TrustProperties match = properties.get(0);
        if (properties.size() > 1) {
            notes.add("The signing certificate matched more than one trusted list "
                    + "entry; the first is reported.");
        }

        TrustServiceStatusAndInformationExtensions status =
                match.getTrustService() == null
                        ? null
                        : match.getTrustService().getCurrent(Date.from(assessmentTime));

        if (status == null) {
            notes.add("No service status was published for the moment of stamping.");
            return null;
        }

        String territory = null;
        Integer sequenceNumber = null;
        Instant issueDate = null;

        TLInfo list = match.getTLInfo();
        if (list != null && list.getParsingCacheInfo() != null) {
            territory = list.getParsingCacheInfo().getTerritory();
            sequenceNumber = list.getParsingCacheInfo().getSequenceNumber();
            issueDate = list.getParsingCacheInfo().getIssueDate() == null
                    ? null
                    : list.getParsingCacheInfo().getIssueDate().toInstant();
        }

        String serviceName = status.getNames() == null || status.getNames().isEmpty()
                ? null
                : status.getNames().values().iterator().next().stream()
                        .findFirst().orElse(null);

        return new TimestampValidationResult.TrustedListEvidence(
                territory,
                sequenceNumber,
                issueDate,
                serviceName,
                status.getType(),
                status.getStatus(),
                status.getStartDate() == null ? null : status.getStartDate().toInstant(),
                assessmentTime);
    }

    private PinnedAnchor matchPinnedAnchor(TimestampToken parsed) {
        CertificateToken signing = signingCertificate(parsed);
        if (signing == null) {
            return null;
        }
        String fingerprint = sha256Hex(signing);
        return pinnedAnchors.stream()
                .filter(a -> a.matches(fingerprint))
                .findFirst()
                .orElse(null);
    }

    private static CertificateToken signingCertificate(TimestampToken parsed) {
        if (parsed.getCandidatesForSigningCertificate() == null) {
            return null;
        }
        var best = parsed.getCandidatesForSigningCertificate().getTheBestCandidate();
        return best == null ? null : best.getCertificateToken();
    }

    private static String sha256Hex(CertificateToken certificate) {
        try {
            byte[] digest = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(certificate.getEncoded());
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(String.format("%02X", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }

    private static Outcome toOutcome(boolean passed) {
        return passed ? Outcome.VALID : Outcome.INVALID;
    }

    private static boolean safely(java.util.function.BooleanSupplier check) {
        try {
            return check.getAsBoolean();
        } catch (Exception e) {
            return false;
        }
    }

    private TimestampValidationResult unableToDetermine(
            Instant genTime, List<String> notes, String reason) {
        notes.add(reason);
        return new TimestampValidationResult(
                genTime,
                new TimestampValidationResult.TokenCheck(
                        Outcome.INDETERMINATE, Outcome.INDETERMINATE, Outcome.INDETERMINATE,
                        null, null, null),
                new TimestampValidationResult.TrustAssessment(
                        TrustLevel.UNKNOWN, Outcome.INDETERMINATE, null, null),
                trustedLists.cacheStatus(null),
                List.copyOf(notes));
    }
}
