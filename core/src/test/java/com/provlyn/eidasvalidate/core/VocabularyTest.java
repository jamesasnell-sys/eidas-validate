package com.provlyn.eidasvalidate.core;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VocabularyTest {

    @Test
    @DisplayName("a check that could not be performed is distinct from one that passed")
    void indeterminateIsNotValid() {
        assertNotEquals(Outcome.VALID, Outcome.INDETERMINATE);
        assertNotEquals(Outcome.INVALID, Outcome.INDETERMINATE);
        assertEquals(3, Outcome.values().length,
                "adding a fourth outcome changes what callers must handle");
    }

    @Test
    @DisplayName("recognised is not a lesser grade of qualified")
    void recognisedIsNotQualified() {
        assertNotEquals(TrustLevel.QUALIFIED, TrustLevel.RECOGNISED);
        assertNotEquals(TrustLevel.QUALIFIED, TrustLevel.UNKNOWN);
    }

    @Test
    @DisplayName("pinned anchor fingerprints compare across presentations")
    void fingerprintNormalisation() {
        PinnedAnchor anchor = new PinnedAnchor(
                "Example Root",
                "27:91:A7:32:4D:B9:FE:74",
                "test fixture");

        assertTrue(anchor.matches("27:91:A7:32:4D:B9:FE:74"));
        assertTrue(anchor.matches("2791a7324db9fe74"));
        assertTrue(anchor.matches("27 91 A7 32 4D B9 FE 74"));
        assertFalse(anchor.matches("0000000000000000"));
        assertFalse(anchor.matches(null));
    }
}
