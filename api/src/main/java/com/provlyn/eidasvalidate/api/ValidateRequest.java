package com.provlyn.eidasvalidate.api;

/**
 * Request body for {@code POST /api/v1/validate}.
 *
 * <p>No document field, by design. The digest-only path is the only one this
 * service exposes over HTTP: a browser computes the digest locally and only
 * those bytes are sent, so the document itself never leaves the caller's
 * machine and this service never has it to retain, mishandle, or log.
 *
 * @param token           base64-encoded RFC 3161 timestamp token (DER, or a
 *                        .tsr response)
 * @param digest          base64-encoded digest of the document the token is
 *                        said to cover; optional. Without it, the message
 *                        imprint check is reported INDETERMINATE rather than
 *                        skipped silently.
 * @param digestAlgorithm name of the algorithm used to produce {@code digest},
 *                        for example {@code SHA-256}; required if digest is
 *                        supplied
 */
public record ValidateRequest(String token, String digest, String digestAlgorithm) {
}
