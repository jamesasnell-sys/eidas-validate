package com.provlyn.eidasvalidate.api;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

import java.time.Duration;

/**
 * Rate limiting configuration.
 *
 * <p>The defaults are set for a verification tool rather than an API a caller
 * would poll: a person checking a handful of tokens will never notice them,
 * while a script hammering the endpoint will. Anyone who genuinely needs more
 * can run their own instance, which is the point of publishing the source.
 */
@Configuration
@EnableConfigurationProperties(RateLimitConfig.RateLimitProperties.class)
public class RateLimitConfig {

    /**
     * @param requests           requests permitted per origin per window
     * @param window             length of the sliding window
     * @param maxTrackedCallers  ceiling on distinct origins held in memory
     * @param behindProxy        whether a trusted proxy sets X-Forwarded-For.
     *                           Must be true on Render, where the service sits
     *                           behind a load balancer and every request would
     *                           otherwise appear to come from one address and
     *                           share a single budget.
     */
    @ConfigurationProperties(prefix = "eidas.rate-limit")
    public record RateLimitProperties(
            Integer requests,
            Duration window,
            Integer maxTrackedCallers,
            Boolean behindProxy) {

        public RateLimitProperties {
            requests = requests == null ? 30 : requests;
            window = window == null ? Duration.ofMinutes(1) : window;
            maxTrackedCallers = maxTrackedCallers == null ? 10_000 : maxTrackedCallers;
            behindProxy = behindProxy != null && behindProxy;
        }
    }

    @Bean
    public RateLimiter rateLimiter(RateLimitProperties properties) {
        return new RateLimiter(
                properties.requests(), properties.window(), properties.maxTrackedCallers());
    }

    @Bean
    public FilterRegistrationBean<RateLimitFilter> rateLimitFilter(
            RateLimiter rateLimiter, RateLimitProperties properties) {
        FilterRegistrationBean<RateLimitFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new RateLimitFilter(rateLimiter, properties.behindProxy()));
        registration.addUrlPatterns("/api/*");
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE + 1);
        return registration;
    }

    /**
     * Ordered ahead of the rate limiter. Rejecting an oversized body is the
     * cheaper check, and doing it first means a large payload is discarded
     * before anything else touches it.
     */
    @Bean
    public FilterRegistrationBean<RequestSizeFilter> requestSizeFilter(
            @Value("${eidas.max-request-bytes:65536}") int maxRequestBytes) {
        FilterRegistrationBean<RequestSizeFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new RequestSizeFilter(maxRequestBytes));
        registration.addUrlPatterns("/api/*");
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return registration;
    }
}
