package com.provlyn.eidasvalidate.api;

import com.provlyn.eidasvalidate.core.TrustedListManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Refreshes trusted list data periodically so a long-running instance does not
 * serve increasingly stale data.
 *
 * <p>Render's free tier suspends this service after fifteen minutes idle, so
 * in practice most refreshes happen at startup ({@link ValidationConfig}'s
 * {@code primeTrustedLists}) rather than on this schedule — this exists for
 * whenever the service is under enough steady traffic to stay warm.
 */
@Component
public class TrustedListRefreshScheduler {

    private static final Logger log = LoggerFactory.getLogger(TrustedListRefreshScheduler.class);

    private final TrustedListManager trustedListManager;

    public TrustedListRefreshScheduler(TrustedListManager trustedListManager) {
        this.trustedListManager = trustedListManager;
    }

    @Scheduled(fixedRateString = "${eidas.refresh-interval:PT6H}")
    public void refresh() {
        ValidationConfig.refreshSafely(trustedListManager, log);
    }
}
