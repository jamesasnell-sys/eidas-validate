package com.provlyn.eidasvalidate.core;

/**
 * The result of a single check.
 *
 * <p>Three outcomes rather than two, so that a check which could not be
 * performed can never be read as one that passed.
 */
public enum Outcome {

    /** The check was performed and passed. */
    VALID,

    /** The check was performed and failed. */
    INVALID,

    /**
     * The check could not be performed, or produced no determination.
     * A missing input, an unreachable trusted list, a stale cache.
     * Never to be rendered to a user as success.
     */
    INDETERMINATE
}
