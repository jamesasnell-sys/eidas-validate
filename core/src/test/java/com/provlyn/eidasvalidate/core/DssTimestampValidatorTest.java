package com.provlyn.eidasvalidate.core;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * These run without network access. Trusted list data is absent, which is
 * exactly the condition under which a validator must not guess.
 */
class DssTimestampValidatorTest {

    @TempDir
    File cacheDirectory;

    private DssTimestampValidator validator() {
        TrustedListManager lists =
                new TrustedListManager(cacheDirectory, Duration.ofHours(12));
        return new DssTimestampValidator(lists, List.of());
    }

    @Test
    @DisplayName("no token supplied yields indeterminate, never a verdict")
    void emptyToken() {
        TimestampValidationResult r = validator().validate(new byte[0]);

        assertEquals(Outcome.INDETERMINATE, r.token().signature());
        assertEquals(Outcome.INDETERMINATE, r.trust().determination());
        assertNotEquals(TrustLevel.QUALIFIED, r.trust().level());
        assertFalse(r.notes().isEmpty(), "an indeterminate result must say why");
    }

    @Test
    @DisplayName("unparseable bytes yield indeterminate with a stated reason")
    void garbageToken() {
        TimestampValidationResult r =
                validator().validate("this is not a timestamp token".getBytes());

        assertEquals(Outcome.INDETERMINATE, r.trust().determination());
        assertEquals(TrustLevel.UNKNOWN, r.trust().level());
        assertFalse(r.notes().isEmpty());
    }

    @Test
    @DisplayName("absent trusted list data is reported stale, not fresh")
    void staleWhenNothingLoaded() {
        TrustedListManager lists =
                new TrustedListManager(cacheDirectory, Duration.ofHours(12));

        assertFalse(lists.isLoaded(),
                "no data should be loaded before a refresh");
        assertTrue(lists.cacheStatus(null).stale(),
                "unknown freshness must read as stale, not as current");
    }

    @Test
    @DisplayName("a wrong-length digest is not treated as a failed match")
    void malformedDigestIsNotAFailedMatch() {
        // Two bytes is not a SHA-256 digest. Reporting INVALID here would tell
        // the caller their document does not match, which is a different and
        // much more alarming statement than the check could not be performed.
        TimestampValidationResult r =
                validator().validateDigest("nonsense".getBytes(), new byte[] {1, 2}, "SHA-256");

        assertNotEquals(Outcome.INVALID, r.token().messageImprint());
    }

    @Test
    @DisplayName("an unknown digest algorithm does not produce a match verdict")
    void unknownDigestAlgorithm() {
        TimestampValidationResult r = validator()
                .validateDigest("nonsense".getBytes(), new byte[32], "SHA-999");

        assertNotEquals(Outcome.VALID, r.token().messageImprint());
    }

    @Test
    @DisplayName("every indeterminate result carries a populated reason")
    void indeterminateAlwaysExplained() {
        List<TimestampValidationResult> results = List.of(
                validator().validate(new byte[0]),
                validator().validate("nonsense".getBytes()));

        for (TimestampValidationResult r : results) {
            if (r.trust().determination() == Outcome.INDETERMINATE) {
                assertFalse(r.notes().isEmpty(),
                        "an indeterminate that says nothing is a silent failure");
            }
        }
    }
}
