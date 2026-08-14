package com.provlyn.eidasvalidate.core;

/**
 * What the issuing authority is, as established independently of the token.
 *
 * <p>This is a separate axis from whether the token's signature verifies.
 * A token forged by an attacker running their own timestamp authority passes
 * the signature check and the message imprint check; only the trust anchor
 * catches it. The two determinations are therefore reported separately and
 * are never combined into a single verdict.
 */
public enum TrustLevel {

    /**
     * Issued by a qualified trust service listed in an EU Trusted List, with
     * a granted status at the time of stamping. Article 41 presumption attaches.
     */
    QUALIFIED,

    /**
     * Issued by an authority we recognise from a pinned anchor set, but which
     * is not a qualified EU trust service. Valid, and no eIDAS presumption.
     * FreeTSA and the common commercial authorities sit here.
     */
    RECOGNISED,

    /**
     * The issuing authority could not be placed. Not evidence of forgery, and
     * not evidence of anything else either.
     */
    UNKNOWN
}
