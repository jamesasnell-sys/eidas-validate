package com.provlyn.eidasvalidate.core;

import eu.europa.esig.dss.model.tsl.TLInfo;
import eu.europa.esig.dss.model.tsl.TLValidationJobSummary;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.tsl.cache.CacheCleaner;
import eu.europa.esig.dss.tsl.function.TLPredicateFactory;
import eu.europa.esig.dss.tsl.job.TLValidationJob;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.tsl.sync.AcceptAllStrategy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Objects;
import java.util.Optional;

/**
 * Holds the European Union trusted list data and keeps it refreshed.
 *
 * <p>The list of trusted lists is fetched from the address published in the
 * Official Journal, its own signature is verified against the certificates
 * announced there, and each member state list is then fetched and verified in
 * turn. Fetching over HTTPS and parsing without checking those signatures would
 * rest the whole determination on TLS and DNS.
 *
 * <p>Refresh is not automatic. A caller drives it, and every result carries the
 * time of the last successful refresh so that a stale answer is visible as such
 * rather than presented as current.
 */
public class TrustedListManager {

    private static final Logger log = LoggerFactory.getLogger(TrustedListManager.class);

    /** Address of the list of trusted lists, as published in the Official Journal. */
    public static final String LOTL_URL =
            "https://ec.europa.eu/tools/lotl/eu-lotl.xml";

    /**
     * Where the Official Journal announces the certificates that sign the list.
     *
     * <p>This notice is superseded whenever the Commission publishes a new one; the
     * current instance is C/2026/1944 (15 April 2026), which replaced OJ C 276
     * (16 August 2019). Update this constant, and {@link #OJ_LOTL_KEYSTORE_RESOURCE},
     * together whenever that happens, or the two fall out of sync.
     */
    public static final String OJ_URL =
            "https://eur-lex.europa.eu/eli/C/2026/1944/oj";

    /**
     * Classpath resource holding the LOTL-signing certificates published in the
     * annex to {@link #OJ_URL}, as a PKCS12 keystore with no password on the
     * individual entries. Six certificates as of the current notice.
     *
     * <p>This is the trust anchor for the whole chain. Without it, DSS fetches and
     * parses the lists but has nothing to check their signatures against, and every
     * validation indication comes back unevaluated rather than PASSED or FAILED.
     */
    public static final String OJ_LOTL_KEYSTORE_RESOURCE = "/oj-lotl-keystore.p12";

    private static final String OJ_LOTL_KEYSTORE_PASSWORD = "changeit";

    private final TrustedListsCertificateSource certificateSource;
    private final TLValidationJob job;
    private final Duration maximumAge;

    private volatile Instant lastRefreshAttempt;

    /**
     * @param cacheDirectory where fetched lists are held between restarts, so that
     *                       a cold start does not leave the service unusable while
     *                       thirty documents are fetched and verified
     * @param maximumAge     beyond which cached data is reported stale
     */
    public TrustedListManager(File cacheDirectory, Duration maximumAge) {
        this.maximumAge = Objects.requireNonNull(maximumAge, "maximumAge");
        this.certificateSource = new TrustedListsCertificateSource();

        LOTLSource lotl = new LOTLSource();
        lotl.setUrl(LOTL_URL);
        lotl.setPivotSupport(true);
        lotl.setCertificateSource(ojCertificateSource());

        // Only timestamping services are retained. The lists carry every kind of
        // qualified trust service, and the rest are weight this service will never
        // consult.
        lotl.setTrustServicePredicate(new TimestampingServicePredicate());

        this.job = new TLValidationJob();
        this.job.setListOfTrustedListSources(lotl);
        this.job.setTrustedListCertificateSource(certificateSource);
        this.job.setOfflineDataLoader(offlineLoader(cacheDirectory));
        this.job.setOnlineDataLoader(onlineLoader(cacheDirectory));
        this.job.setSynchronizationStrategy(new AcceptAllStrategy());
        this.job.setCacheCleaner(cacheCleaner(cacheDirectory));
    }

    /**
     * Load whatever is already on disk. Fast, and does not reach the network.
     * A service that has never refreshed online has nothing to load.
     */
    public void loadFromCache() {
        job.offlineRefresh();
        log.info("Trusted lists loaded from cache: {} certificates across {} entities",
                certificateSource.getNumberOfCertificates(),
                certificateSource.getNumberOfEntities());
    }

    /**
     * Fetch and verify from source. Costly, and the only way the data becomes
     * current.
     */
    public void refresh() {
        job.onlineRefresh();
        lastRefreshAttempt = Instant.now();
        log.info("Trusted lists refreshed: {} certificates across {} entities",
                certificateSource.getNumberOfCertificates(),
                certificateSource.getNumberOfEntities());
    }

    public TrustedListsCertificateSource certificateSource() {
        return certificateSource;
    }

    public TLValidationJobSummary summary() {
        return certificateSource.getSummary();
    }

    /**
     * Whether any trusted list data has been loaded at all. A determination made
     * against no data is not a determination, and callers must treat this as
     * grounds for INDETERMINATE rather than proceeding.
     */
    public boolean isLoaded() {
        return certificateSource.getNumberOfCertificates() > 0;
    }

    /**
     * Freshness of the list data, for inclusion in every result.
     *
     * @param territory two-letter country code of the member state list consulted,
     *                  or null where only the list of trusted lists is relevant
     */
    public TimestampValidationResult.CacheStatus cacheStatus(String territory) {
        Instant lotlSync = lotlSynchronisation().orElse(null);
        Instant listSync = territory == null
                ? null
                : listSynchronisation(territory).orElse(null);

        Instant oldest = older(lotlSync, listSync);
        boolean stale = oldest == null
                || oldest.isBefore(Instant.now().minus(maximumAge));

        return new TimestampValidationResult.CacheStatus(lotlSync, listSync, stale);
    }

    private Optional<Instant> lotlSynchronisation() {
        TLValidationJobSummary s = summary();
        if (s == null || s.getLOTLInfos().isEmpty()) {
            return Optional.empty();
        }
        return toInstant(s.getLOTLInfos().get(0)
                .getParsingCacheInfo().getLastSuccessSynchronizationTime());
    }

    private Optional<Instant> listSynchronisation(String territory) {
        return findList(territory)
                .flatMap(tl -> toInstant(
                        tl.getParsingCacheInfo().getLastSuccessSynchronizationTime()));
    }

    /**
     * Locate the member state list for a territory, for evidence purposes.
     */
    public Optional<TLInfo> findList(String territory) {
        TLValidationJobSummary s = summary();
        if (s == null || territory == null) {
            return Optional.empty();
        }
        return s.getLOTLInfos().stream()
                .flatMap(lotl -> lotl.getTLInfos().stream())
                .filter(tl -> tl.getParsingCacheInfo() != null)
                .filter(tl -> territory.equalsIgnoreCase(
                        tl.getParsingCacheInfo().getTerritory()))
                .findFirst();
    }

    private static Optional<Instant> toInstant(Date date) {
        return Optional.ofNullable(date).map(Date::toInstant);
    }

    private static Instant older(Instant a, Instant b) {
        if (a == null) {
            return b;
        }
        if (b == null) {
            return a;
        }
        return a.isBefore(b) ? a : b;
    }

    /**
     * Loads the OJ-published LOTL-signing certificates that DSS uses to verify
     * the LOTL's own signature and, going backwards through pivots, the signature
     * of each preceding LOTL instance.
     *
     * <p>Sourced from the annex to {@link #OJ_URL}, not from the LOTL itself or
     * any third party — trusting the LOTL to supply the certificate that verifies
     * the LOTL would be circular.
     */
    private static KeyStoreCertificateSource ojCertificateSource() {
        try (InputStream keystoreStream =
                TrustedListManager.class.getResourceAsStream(OJ_LOTL_KEYSTORE_RESOURCE)) {
            if (keystoreStream == null) {
                throw new IllegalStateException(
                        "OJ LOTL keystore resource not found on classpath: "
                                + OJ_LOTL_KEYSTORE_RESOURCE);
            }
            return new KeyStoreCertificateSource(
                    keystoreStream, "PKCS12", OJ_LOTL_KEYSTORE_PASSWORD.toCharArray());
        } catch (IOException e) {
            throw new UncheckedIOException(
                    "Failed to load OJ LOTL keystore from " + OJ_LOTL_KEYSTORE_RESOURCE, e);
        }
    }

    private static FileCacheDataLoader offlineLoader(File cacheDirectory) {
        FileCacheDataLoader loader = new FileCacheDataLoader();
        loader.setCacheExpirationTime(Long.MAX_VALUE);
        loader.setDataLoader(new IgnoreDataLoader());
        loader.setFileCacheDirectory(cacheDirectory);
        return loader;
    }

    private static FileCacheDataLoader onlineLoader(File cacheDirectory) {
        FileCacheDataLoader loader = new FileCacheDataLoader();
        loader.setCacheExpirationTime(0);
        CommonsDataLoader http = new CommonsDataLoader();
        http.setTimeoutConnection(30_000);
        http.setTimeoutResponse(60_000);
        loader.setDataLoader(http);
        loader.setFileCacheDirectory(cacheDirectory);
        return loader;
    }

    private static CacheCleaner cacheCleaner(File cacheDirectory) {
        CacheCleaner cleaner = new CacheCleaner();
        cleaner.setCleanMemory(true);
        cleaner.setCleanFileSystem(true);
        cleaner.setDSSFileLoader(offlineLoader(cacheDirectory));
        return cleaner;
    }

    /** Predicate over trust services, retaining only timestamping. */
    static final class TimestampingServicePredicate
            implements java.util.function.Predicate<
                    eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceType> {

        private static final String TIMESTAMPING_SERVICE_TYPE =
                "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST";
        private static final String TSA_SERVICE_TYPE =
                "http://uri.etsi.org/TrstSvc/Svctype/TSA";

        @Override
        public boolean test(eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceType service) {
            if (service == null || service.getServiceInformation() == null) {
                return false;
            }
            String type = service.getServiceInformation().getServiceTypeIdentifier();
            return TIMESTAMPING_SERVICE_TYPE.equals(type) || TSA_SERVICE_TYPE.equals(type);
        }
    }

    /** A loader that never reaches the network, for the offline path. */
    static final class IgnoreDataLoader
            implements eu.europa.esig.dss.spi.client.http.DataLoader {

        @Override
        public byte[] get(String url) {
            return null;
        }

        @Override
        public eu.europa.esig.dss.spi.client.http.DataLoader.DataAndUrl get(
                java.util.List<String> urlStrings) {
            return null;
        }

        @Override
        public byte[] post(String url, byte[] content) {
            return null;
        }

        @Override
        public void setContentType(String contentType) {
            // no network, nothing to set
        }
    }
}
