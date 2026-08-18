package com.provlyn.eidasvalidate.api;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RateLimiterTest {

    @Test
    void permitsUpToTheLimitThenRefuses() {
        RateLimiter limiter = new RateLimiter(3, Duration.ofMinutes(1), 100);

        assertTrue(limiter.tryAcquire("caller-a"));
        assertTrue(limiter.tryAcquire("caller-a"));
        assertTrue(limiter.tryAcquire("caller-a"));
        assertFalse(limiter.tryAcquire("caller-a"), "fourth request exceeds a limit of three");
    }

    @Test
    void callersDoNotShareABudget() {
        RateLimiter limiter = new RateLimiter(2, Duration.ofMinutes(1), 100);

        assertTrue(limiter.tryAcquire("caller-a"));
        assertTrue(limiter.tryAcquire("caller-a"));
        assertFalse(limiter.tryAcquire("caller-a"));

        // One caller exhausting its budget must not affect another.
        assertTrue(limiter.tryAcquire("caller-b"));
        assertTrue(limiter.tryAcquire("caller-b"));
    }

    @Test
    void requestsLeaveTheWindow() throws InterruptedException {
        RateLimiter limiter = new RateLimiter(2, Duration.ofMillis(200), 100);

        assertTrue(limiter.tryAcquire("caller"));
        assertTrue(limiter.tryAcquire("caller"));
        assertFalse(limiter.tryAcquire("caller"));

        Thread.sleep(250);

        assertTrue(limiter.tryAcquire("caller"), "the window should have moved past the earlier requests");
    }

    /**
     * An unbounded map keyed on caller-supplied input is a denial of service in
     * itself. Beyond the cap the limiter must refuse unrecognised callers rather
     * than continue allocating.
     */
    @Test
    void refusesNewCallersBeyondTheTrackingCap() {
        RateLimiter limiter = new RateLimiter(10, Duration.ofMinutes(1), 2);

        assertTrue(limiter.tryAcquire("caller-1"));
        assertTrue(limiter.tryAcquire("caller-2"));
        assertFalse(limiter.tryAcquire("caller-3"), "a third caller exceeds a cap of two");

        // Callers already being tracked keep working.
        assertTrue(limiter.tryAcquire("caller-1"));
    }

    @Test
    void retryAfterIsPositiveAndWithinTheWindow() {
        RateLimiter limiter = new RateLimiter(1, Duration.ofSeconds(60), 100);
        limiter.tryAcquire("caller");
        assertFalse(limiter.tryAcquire("caller"));

        long retryAfter = limiter.retryAfterSeconds("caller");
        assertTrue(retryAfter >= 1, "retry-after must be at least one second");
        assertTrue(retryAfter <= 60, "retry-after must not exceed the window");
    }

    @Test
    void unknownCallerIsToldToWaitTheFullWindow() {
        RateLimiter limiter = new RateLimiter(5, Duration.ofSeconds(30), 100);
        assertEquals(30, limiter.retryAfterSeconds("never-seen"));
    }
}
