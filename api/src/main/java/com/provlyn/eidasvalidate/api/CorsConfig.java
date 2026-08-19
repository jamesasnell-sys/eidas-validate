package com.provlyn.eidasvalidate.api;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.List;

/**
 * Allows the validation endpoint to be called from a browser.
 *
 * <p>Without this a page served from provlyn.com cannot read the response: the
 * browser makes the request but blocks the result, because the service does not
 * say it permits that origin. The API remains open to non-browser callers
 * regardless — CORS is a browser mechanism, not an access control — so this
 * only affects whether a web page can use the tool.
 *
 * <p>Specific origins rather than a wildcard. The tool is meant to be embedded
 * on Provlyn's own site, so those are the origins named. Anyone running their
 * own instance sets their own list. A wildcard would work but claims more than
 * is meant, and this service's whole posture is to claim only what it can show.
 */
@Configuration
public class CorsConfig {

    /**
     * Comma-separated list of allowed origins. Defaults to the Provlyn
     * production and staging sites plus local development. Overridable per
     * deployment via CORS_ALLOWED_ORIGINS.
     */
    @Bean
    public FilterRegistrationBean<CorsFilter> corsFilter(
            @Value("${eidas.cors.allowed-origins:"
                    + "https://www.provlyn.com,"
                    + "https://provlyn.com,"
                    + "https://staging.provlyn.com,"
                    + "http://localhost:3000}") String allowedOrigins) {

        CorsConfiguration config = new CorsConfiguration();
        // Only the verbs the API actually uses. A preflight for anything else
        // is refused rather than waved through.
        config.setAllowedMethods(List.of("GET", "POST", "OPTIONS"));
        config.setAllowedHeaders(List.of("Content-Type"));
        // No credentials are involved — the endpoint takes no cookies or auth —
        // so this stays false, which also keeps a wildcard from ever implying
        // credentialed access.
        config.setAllowCredentials(false);
        config.setMaxAge(3600L);

        for (String origin : allowedOrigins.split(",")) {
            String trimmed = origin.trim();
            if (!trimmed.isEmpty()) {
                config.addAllowedOrigin(trimmed);
            }
        }

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", config);

        FilterRegistrationBean<CorsFilter> registration =
                new FilterRegistrationBean<>(new CorsFilter(source));
        // Ahead of the size and rate-limit filters, so a browser preflight is
        // answered before either of them runs.
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return registration;
    }
}
