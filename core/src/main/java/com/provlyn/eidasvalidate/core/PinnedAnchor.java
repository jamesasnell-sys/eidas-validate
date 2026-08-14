package com.provlyn.eidasvalidate.core;

/**
 * An authority recognised by fingerprint rather than through a trusted list.
 *
 * <p>These exist because people will submit tokens from FreeTSA and from the
 * common commercial authorities, and a tool that shrugs at them is not useful.
 * A match yields {@link TrustLevel#RECOGNISED}, never QUALIFIED. Nothing in
 * this set carries an eIDAS presumption, and the distinction is not a matter
 * of degree.
 *
 * @param name              the name this service knows the anchor by
 * @param certificateSha256 fingerprint of the root, uppercase hex, colon-separated
 * @param note              provenance of the fingerprint, for the record
 */
public record PinnedAnchor(
        String name,
        String certificateSha256,
        String note) {

    /**
     * Normalised comparison. Fingerprints arrive in several presentations.
     */
    public boolean matches(String candidateSha256) {
        if (candidateSha256 == null) {
            return false;
        }
        return normalise(certificateSha256).equals(normalise(candidateSha256));
    }

    private static String normalise(String fingerprint) {
        return fingerprint.replace(":", "").replace(" ", "").toUpperCase();
    }
}
