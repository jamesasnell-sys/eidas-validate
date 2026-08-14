package com.provlyn.eidasvalidate.core;

import java.time.Instant;

/**
 * Validates an RFC 3161 timestamp token.
 */
public interface TimestampValidator {

    /**
     * Validate a token on its own. The message imprint cannot be checked
     * without the document, so it is reported INDETERMINATE.
     *
     * @param token DER-encoded RFC 3161 token, or a .tsr response
     */
    TimestampValidationResult validate(byte[] token);

    /**
     * Validate a token against the document it is said to cover.
     *
     * @param token    DER-encoded RFC 3161 token, or a .tsr response
     * @param document the bytes the token should attest to
     */
    TimestampValidationResult validate(byte[] token, byte[] document);

    /**
     * Validate against a digest the caller computed, where the document itself
     * is not to be transmitted.
     *
     * @param token           DER-encoded RFC 3161 token, or a .tsr response
     * @param digest          the digest bytes
     * @param digestAlgorithm algorithm name, for example SHA-256
     */
    TimestampValidationResult validateDigest(byte[] token, byte[] digest, String digestAlgorithm);

    /**
     * Assess trust as at a stated instant rather than at the token's own
     * genTime. Present for testing status history; production callers should
     * use the genTime the token asserts.
     */
    TimestampValidationResult validateAsAt(byte[] token, byte[] document, Instant assessmentTime);
}
