package com.provlyn.eidasvalidate.api;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * Binds {@code eidas.cache.*} from application configuration.
 *
 * @param maxAge    beyond which trusted list data is reported stale
 * @param directory where fetched lists are held between restarts
 */
@ConfigurationProperties(prefix = "eidas.cache")
public record CacheProperties(Duration maxAge, String directory) {
}
