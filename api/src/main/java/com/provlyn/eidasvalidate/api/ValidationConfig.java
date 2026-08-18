package com.provlyn.eidasvalidate.api;

import com.provlyn.eidasvalidate.core.DssTimestampValidator;
import com.provlyn.eidasvalidate.core.PinnedAnchor;
import com.provlyn.eidasvalidate.core.TimestampValidator;
import com.provlyn.eidasvalidate.core.TrustedListManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

import java.io.File;
import java.util.List;
import java.util.concurrent.Executors;

/**
 * Wires the core validation logic into the Spring application context.
 *
 * <p>Trusted list loading is kept off the startup path. A cold container should
 * answer health checks immediately; the first live refresh happens in the
 * background afterwards, and requests arriving before it completes are
 * reported INDETERMINATE with the reason stated, not blocked or guessed at.
 */
@Configuration
@EnableScheduling
@EnableConfigurationProperties(CacheProperties.class)
public class ValidationConfig {

    private static final Logger log = LoggerFactory.getLogger(ValidationConfig.class);

    @Bean
    public TrustedListManager trustedListManager(CacheProperties cacheProperties) {
        File cacheDirectory = new File(cacheProperties.directory());
        cacheDirectory.mkdirs();
        return new TrustedListManager(cacheDirectory, cacheProperties.maxAge());
    }

    /**
     * Recognised authorities outside the EU trusted list framework: FreeTSA and
     * the common commercial timestamping services. Matching one of these yields
     * RECOGNISED, never QUALIFIED, and carries no eIDAS presumption.
     *
     * <p>Empty for now. Populating it means sourcing each authority's actual
     * root certificate fingerprint from that authority's own published material,
     * the same discipline applied to the OJ trust anchor — not copying a
     * fingerprint from a search result or fabricating one. Until that sourcing
     * work is done, tokens from these authorities are correctly reported
     * UNKNOWN rather than incorrectly reported RECOGNISED against a guess.
     */
    @Bean
    public List<PinnedAnchor> pinnedAnchors() {
        return List.of();
    }

    @Bean
    public TimestampValidator timestampValidator(
            TrustedListManager trustedListManager, List<PinnedAnchor> pinnedAnchors) {
        return new DssTimestampValidator(trustedListManager, pinnedAnchors);
    }

    /**
     * Loads whatever is on disk immediately, so a cold container can answer
     * requests (as stale, if the cache is old, or INDETERMINATE if there is
     * nothing cached at all) without waiting on the network. The live refresh
     * that follows runs on its own thread and does not hold up startup.
     */
    @Bean
    public ApplicationRunner primeTrustedLists(
            TrustedListManager trustedListManager,
            @Value("${eidas.refresh-on-startup:true}") boolean refreshOnStartup) {
        return (ApplicationArguments args) -> {
            try {
                trustedListManager.loadFromCache();
            } catch (Exception e) {
                log.warn("No usable trusted list cache on disk at startup", e);
            }
            if (refreshOnStartup) {
                Executors.newSingleThreadExecutor(r -> {
                    Thread t = new Thread(r, "trusted-list-startup-refresh");
                    t.setDaemon(true);
                    return t;
                }).submit(() -> refreshSafely(trustedListManager, log));
            }
        };
    }

    /** Shared with {@link TrustedListRefreshScheduler}, since @Scheduled methods take no parameters. */
    static void refreshSafely(TrustedListManager trustedListManager, Logger log) {
        try {
            trustedListManager.refresh();
        } catch (Exception e) {
            log.warn("Trusted list refresh failed; previously loaded data, if any, remains in use", e);
        }
    }
}
