package com.provlyn.eidasvalidate.core;

import java.time.Instant;
import java.util.List;

/**
 * The complete outcome of validating one RFC 3161 timestamp token.
 *
 * <p>Structured so that a caller cannot render a single green tick. The token
 * check and the trust assessment are separate fields with separate outcomes,
 * and the evidence behind the trust assessment travels with it.
 *
 * @param genTime          the time asserted by the token, as issued
 * @param token            structural validity: signature, imprint, certificate
 * @param trust            what the issuing authority is, established independently
 * @param cache            freshness of the trusted list data behind the assessment
 * @param notes            observations that qualify the result without altering it
 */
public record TimestampValidationResult(
        Instant genTime,
        TokenCheck token,
        TrustAssessment trust,
        CacheStatus cache,
        List<String> notes) {

    /**
     * Structural validity of the token itself.
     *
     * <p>Every field here can pass on a token forged by an attacker who runs
     * their own authority. None of it establishes trust.
     *
     * @param signature            token signature verifies against the embedded certificate
     * @param messageImprint       document hash matches the token's signed content;
     *                             INDETERMINATE where no document was supplied
     * @param certificateValidity  the signing certificate was within its validity
     *                             window at genTime, not at the present moment
     * @param digestAlgorithm      algorithm named in the message imprint
     * @param issuerDn             distinguished name asserted by the signing certificate
     * @param certificateSha256    fingerprint of the signing certificate, uppercase hex
     */
    public record TokenCheck(
            Outcome signature,
            Outcome messageImprint,
            Outcome certificateValidity,
            String digestAlgorithm,
            String issuerDn,
            String certificateSha256) {
    }

    /**
     * What the issuing authority is, and the evidence for that finding.
     *
     * @param level              the finding
     * @param determination      whether the finding could be made at all
     * @param trustedList        trusted list evidence, null where the anchor was pinned
     * @param pinnedAnchor       pinned anchor evidence, null where the finding came from a list
     */
    public record TrustAssessment(
            TrustLevel level,
            Outcome determination,
            TrustedListEvidence trustedList,
            PinnedAnchorEvidence pinnedAnchor) {
    }

    /**
     * Where a qualified finding came from, in enough detail to be checked by
     * someone who does not trust this service.
     *
     * @param countryCode           member state whose list carries the service
     * @param listSequenceNumber    sequence number of the list consulted
     * @param listIssueDate         issue date of that list
     * @param serviceName           service name as published
     * @param serviceTypeIdentifier ETSI service type URI
     * @param statusUri             status URI in force at the stamping time
     * @param statusStartingTime    when that status took effect
     * @param assessedAt            the instant the status was assessed against,
     *                              which is the stamping time and not the present
     */
    public record TrustedListEvidence(
            String countryCode,
            Integer listSequenceNumber,
            Instant listIssueDate,
            String serviceName,
            String serviceTypeIdentifier,
            String statusUri,
            Instant statusStartingTime,
            Instant assessedAt) {
    }

    /**
     * Where a recognised finding came from.
     *
     * @param anchorName        the name this service knows the anchor by
     * @param certificateSha256 pinned fingerprint that matched, uppercase hex
     */
    public record PinnedAnchorEvidence(
            String anchorName,
            String certificateSha256) {
    }

    /**
     * Freshness of the trusted list data behind the assessment.
     *
     * <p>Stale data can report qualified status for a service withdrawn last
     * week. That risk is stated in the result rather than hidden.
     *
     * @param lotlLastRefreshed  when the List of Trusted Lists was last fetched
     * @param listLastRefreshed  when the member state list consulted was last fetched
     * @param stale              true where either exceeds the configured maximum age
     */
    public record CacheStatus(
            Instant lotlLastRefreshed,
            Instant listLastRefreshed,
            boolean stale) {
    }
}
