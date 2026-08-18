package com.provlyn.eidasvalidate.api;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;

import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Cover for the HTTP layer, which had none. Every check here was previously
 * confirmed by hand with curl and then forgotten, which is the same as not
 * having been checked at all.
 *
 * <p>Trusted list refresh is disabled, so these run without network. Trust
 * outcomes are therefore not asserted; what is asserted is the contract the
 * endpoint offers a caller, and the limits that stand in front of it.
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "eidas.refresh-on-startup=false",
        "eidas.rate-limit.requests=1000",
        "eidas.rate-limit.window=PT1M",
        "eidas.max-request-bytes=4096"
})
class ValidateEndpointTest {

    @Autowired
    private MockMvc mockMvc;

    private static String fixtureBase64(String name) throws Exception {
        try (InputStream in = ValidateEndpointTest.class.getResourceAsStream("/fixtures/" + name)) {
            assertNotNull(in, "missing fixture: " + name);
            return Base64.getEncoder().encodeToString(in.readAllBytes());
        }
    }

    private static String digestBase64(String name) throws Exception {
        try (InputStream in = ValidateEndpointTest.class.getResourceAsStream("/fixtures/" + name)) {
            assertNotNull(in, "missing fixture: " + name);
            return Base64.getEncoder().encodeToString(
                    MessageDigest.getInstance("SHA-256").digest(in.readAllBytes()));
        }
    }

    @Test
    @DisplayName("a token and matching digest are accepted and the imprint reported valid")
    void validatesGenuineToken() throws Exception {
        String body = "{\"token\":\"" + fixtureBase64("genuine-token.der")
                + "\",\"digest\":\"" + digestBase64("document.txt")
                + "\",\"digestAlgorithm\":\"SHA-256\"}";

        mockMvc.perform(post("/api/v1/validate")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token.signature").value("VALID"))
                .andExpect(jsonPath("$.token.messageImprint").value("VALID"));
    }

    @Test
    @DisplayName("a digest for a different document is reported invalid, not valid")
    void detectsAlteredDocument() throws Exception {
        String body = "{\"token\":\"" + fixtureBase64("genuine-token.der")
                + "\",\"digest\":\"" + digestBase64("document-altered.txt")
                + "\",\"digestAlgorithm\":\"SHA-256\"}";

        mockMvc.perform(post("/api/v1/validate")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token.messageImprint").value("INVALID"))
                .andExpect(jsonPath("$.token.signature").value("VALID"));
    }

    @Test
    @DisplayName("a token from an authority outside the trusted lists is never qualified")
    void unrecognisedAuthorityIsNotQualified() throws Exception {
        String body = "{\"token\":\"" + fixtureBase64("forged-token.der") + "\"}";

        mockMvc.perform(post("/api/v1/validate")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.trust.level").value("UNKNOWN"));
    }

    @Test
    @DisplayName("a missing token is refused with a stated reason")
    void missingTokenIsRefused() throws Exception {
        mockMvc.perform(post("/api/v1/validate")
                        .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").exists());
    }

    @Test
    @DisplayName("a digest without its algorithm is refused rather than guessed at")
    void digestWithoutAlgorithmIsRefused() throws Exception {
        String body = "{\"token\":\"" + fixtureBase64("genuine-token.der")
                + "\",\"digest\":\"" + digestBase64("document.txt") + "\"}";

        mockMvc.perform(post("/api/v1/validate")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("input that is not base64 is refused")
    void nonBase64IsRefused() throws Exception {
        mockMvc.perform(post("/api/v1/validate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"not base64 at all !!!\"}"))
                .andExpect(status().isBadRequest());
    }

    /**
     * The ceiling exists because several parser faults of the kind fixed in
     * recent BouncyCastle releases are unbounded allocations driven by
     * attacker-declared lengths. A body this size must be refused before
     * anything parses it.
     */
    @Test
    @DisplayName("an oversized body is refused with 413")
    void oversizedBodyIsRefused() throws Exception {
        String body = "{\"token\":\"" + "A".repeat(20000) + "\"}";

        mockMvc.perform(post("/api/v1/validate")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isPayloadTooLarge())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON));
    }

    @Test
    @DisplayName("health is reachable and not subject to the rate limit")
    void healthIsNotRateLimited() throws Exception {
        // Health is exempt from the limit entirely, so volume is irrelevant here.
        for (int i = 0; i < 12; i++) {
            mockMvc.perform(get("/actuator/health")).andExpect(status().isOk());
        }
    }
}
