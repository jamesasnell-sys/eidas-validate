package com.provlyn.eidasvalidate.api;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Rate limiting at the HTTP layer, including the regression that matters most:
 * the limit read the first X-Forwarded-For entry, which a caller supplies, so
 * rotating that header gave an unlimited budget. It now reads the last entry,
 * which is the one this service's own proxy appended.
 *
 * <p>Its own property set, so Spring gives this class a separate context and
 * the limiter's state is not shared with the endpoint tests.
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "eidas.refresh-on-startup=false",
        "eidas.rate-limit.requests=3",
        "eidas.rate-limit.window=PT5M",
        "eidas.rate-limit.behind-proxy=true"
})
class RateLimitFilterTest {

    private static final String BODY = "{\"token\":\"AAAA\"}";

    @Autowired
    private MockMvc mockMvc;

    private int postForwardedFor(String forwardedFor) throws Exception {
        return mockMvc.perform(post("/api/v1/validate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("X-Forwarded-For", forwardedFor)
                        .content(BODY))
                .andReturn().getResponse().getStatus();
    }

    /**
     * The caller varies the value they control on every request. The proxy
     * entry, appended last, stays constant, so the budget must still run out.
     * Reading the leftmost entry here would let every request look like a new
     * origin and the limit would never engage.
     */
    @Test
    @DisplayName("rotating the client-supplied X-Forwarded-For does not evade the limit")
    void spoofedForwardedForDoesNotBypass() throws Exception {
        int refusals = 0;
        for (int i = 1; i <= 8; i++) {
            int status = postForwardedFor("203.0.113." + i + ", 10.0.0.7");
            if (status == 429) {
                refusals++;
            }
        }

        assertTrue(refusals > 0,
                "a caller rotating the header they control must still meet the limit");
    }

    @Test
    @DisplayName("callers arriving via different proxy entries keep separate budgets")
    void distinctCallersAreNotConflated() throws Exception {
        // Exhaust one caller.
        for (int i = 0; i < 6; i++) {
            postForwardedFor("198.51.100.1, 10.1.1.1");
        }

        assertEquals(200, postForwardedFor("198.51.100.1, 10.2.2.2"),
                "a different origin must not inherit another's exhausted budget");
    }

    @Test
    @DisplayName("a refusal states when to retry")
    void refusalCarriesRetryAfter() throws Exception {
        String caller = "198.51.100.9, 10.3.3.3";
        MvcResult refused = null;

        for (int i = 0; i < 8; i++) {
            MvcResult result = mockMvc.perform(post("/api/v1/validate")
                            .contentType(MediaType.APPLICATION_JSON)
                            .header("X-Forwarded-For", caller)
                            .content(BODY))
                    .andReturn();
            if (result.getResponse().getStatus() == 429) {
                refused = result;
                break;
            }
        }

        assertNotNull(refused, "the limit should have engaged within eight requests");
        String retryAfter = refused.getResponse().getHeader(HttpHeaders.RETRY_AFTER);
        assertNotNull(retryAfter, "a refusal must say when to come back");
        assertTrue(Integer.parseInt(retryAfter) > 0);
    }
}
