package com.provlyn.eidasvalidate.api;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Deque;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A fixed-capacity sliding window rate limiter, held entirely in memory.
 *
 * <p>The service is public and unauthenticated by design, so something has to
 * stand between it and abuse. Authentication would undercut the argument the
 * service exists to make — that verification should not require an account with
 * the party doing the verifying — so the limit is applied by origin instead.
 *
 * <p>Callers are identified by a salted hash of their address, never the address
 * itself. The salt is generated fresh at startup and never leaves the process,
 * so the stored keys cannot be reversed to addresses even by whoever holds the
 * memory, and nothing survives a restart. This keeps the limiter consistent with
 * the promise that the service retains nothing about who verified what.
 *
 * <p>Total tracked callers are capped. An unbounded map keyed on attacker-supplied
 * input is itself a denial of service, so beyond the cap the limiter fails closed
 * for unrecognised callers rather than growing without limit.
 */
public class RateLimiter {

    private final int maxRequests;
    private final Duration window;
    private final int maxTrackedCallers;
    private final byte[] salt;

    private final Map<String, Deque<Instant>> hits = new ConcurrentHashMap<>();
    private final AtomicInteger trackedCallers = new AtomicInteger();

    /**
     * @param maxRequests       requests permitted per caller within the window
     * @param window            length of the sliding window
     * @param maxTrackedCallers ceiling on distinct callers held in memory
     */
    public RateLimiter(int maxRequests, Duration window, int maxTrackedCallers) {
        this.maxRequests = maxRequests;
        this.window = window;
        this.maxTrackedCallers = maxTrackedCallers;
        this.salt = new byte[32];
        new SecureRandom().nextBytes(this.salt);
    }

    /**
     * Record a request and report whether it is within the limit.
     *
     * @param callerIdentifier the caller's address, hashed before use and never stored
     * @return true where the request may proceed
     */
    public boolean tryAcquire(String callerIdentifier) {
        String key = hash(callerIdentifier);
        Instant now = Instant.now();
        Instant cutoff = now.minus(window);

        Deque<Instant> timestamps = hits.get(key);
        if (timestamps == null) {
            // Only admit a new caller if there is room. Failing closed here is
            // deliberate: an attacker rotating source addresses would otherwise
            // grow this map until the process runs out of memory.
            if (trackedCallers.get() >= maxTrackedCallers) {
                sweep(cutoff);
                if (trackedCallers.get() >= maxTrackedCallers) {
                    return false;
                }
            }
            timestamps = new ConcurrentLinkedDeque<>();
            Deque<Instant> existing = hits.putIfAbsent(key, timestamps);
            if (existing == null) {
                trackedCallers.incrementAndGet();
            } else {
                timestamps = existing;
            }
        }

        synchronized (timestamps) {
            while (!timestamps.isEmpty() && timestamps.peekFirst().isBefore(cutoff)) {
                timestamps.pollFirst();
            }
            if (timestamps.size() >= maxRequests) {
                return false;
            }
            timestamps.addLast(now);
            return true;
        }
    }

    /** Seconds until the caller's oldest request leaves the window, for Retry-After. */
    public long retryAfterSeconds(String callerIdentifier) {
        Deque<Instant> timestamps = hits.get(hash(callerIdentifier));
        if (timestamps == null) {
            return window.toSeconds();
        }
        synchronized (timestamps) {
            Instant oldest = timestamps.peekFirst();
            if (oldest == null) {
                return window.toSeconds();
            }
            long remaining = Duration.between(Instant.now(), oldest.plus(window)).toSeconds();
            return Math.max(1, remaining);
        }
    }

    /** Drop callers with no activity inside the window. */
    private void sweep(Instant cutoff) {
        Iterator<Map.Entry<String, Deque<Instant>>> it = hits.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, Deque<Instant>> entry = it.next();
            Deque<Instant> timestamps = entry.getValue();
            synchronized (timestamps) {
                while (!timestamps.isEmpty() && timestamps.peekFirst().isBefore(cutoff)) {
                    timestamps.pollFirst();
                }
                if (timestamps.isEmpty()) {
                    it.remove();
                    trackedCallers.decrementAndGet();
                }
            }
        }
    }

    /**
     * Salted hash of the caller identifier. The address never enters the map,
     * so the limiter's state discloses nothing about who called.
     */
    private String hash(String callerIdentifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(salt);
            digest.update(String.valueOf(callerIdentifier).getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(digest.digest());
        } catch (Exception e) {
            // Without a usable digest the limiter cannot identify callers at
            // all. Returning a shared key makes every caller share one budget,
            // which is restrictive rather than permissive.
            return "unhashed";
        }
    }
}
