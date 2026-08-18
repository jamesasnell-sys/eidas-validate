package com.provlyn.eidasvalidate.api;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Applies the rate limit to validation requests.
 *
 * <p>Health and info endpoints are left alone so that a platform health check
 * cannot exhaust the budget and take the service down by appearing unhealthy.
 */
public class RateLimitFilter extends OncePerRequestFilter {

    private static final String RATE_LIMITED_PATH_PREFIX = "/api/";

    private final RateLimiter rateLimiter;
    private final boolean behindProxy;

    /**
     * @param rateLimiter the limiter to apply
     * @param behindProxy whether a trusted reverse proxy sits in front of this
     *                    service and sets X-Forwarded-For. False by default:
     *                    honouring that header when nothing sets it lets any
     *                    caller forge an address and evade the limit entirely.
     */
    public RateLimitFilter(RateLimiter rateLimiter, boolean behindProxy) {
        this.rateLimiter = rateLimiter;
        this.behindProxy = behindProxy;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith(RATE_LIMITED_PATH_PREFIX);
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String caller = callerIdentifier(request);

        if (!rateLimiter.tryAcquire(caller)) {
            long retryAfter = rateLimiter.retryAfterSeconds(caller);
            response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
            response.setHeader("Retry-After", String.valueOf(retryAfter));
            // Character encoding set explicitly: without it the container falls
            // back to a platform default that mangles anything non-ASCII.
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            response.getWriter().write(
                    "{\"error\":\"Rate limit exceeded. This service is public and "
                            + "unauthenticated, so the limit is applied per origin. "
                            + "Retry in " + retryAfter + " seconds, or run your own "
                            + "instance. The source is published.\"}");
            return;
        }

        chain.doFilter(request, response);
    }

    /**
     * The caller's address.
     *
     * <p>X-Forwarded-For is only consulted where a trusted proxy is known to be
     * in front, because the header is set by the client otherwise and would let
     * anyone present a fresh address per request. Where it is consulted, only
     * the first entry is taken: a proxy appends, so later entries are whatever
     * the client sent.
     */
    private String callerIdentifier(HttpServletRequest request) {
        if (behindProxy) {
            String forwarded = request.getHeader("X-Forwarded-For");
            if (forwarded != null && !forwarded.isBlank()) {
                int comma = forwarded.indexOf(',');
                String first = comma < 0 ? forwarded : forwarded.substring(0, comma);
                first = first.trim();
                if (!first.isEmpty()) {
                    return first;
                }
            }
        }
        String remote = request.getRemoteAddr();
        return remote == null ? "unknown" : remote;
    }
}
