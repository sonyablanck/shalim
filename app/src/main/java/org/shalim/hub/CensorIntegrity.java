package org.shalim.hub;

import java.time.Instant;

/**
 * Whether a hub's censor artefact is the one it is supposed to be running.
 *
 * <p>Separate from {@code HubPolicy} because it is observed state rather than
 * configuration, and it is the trigger for restricting a hub. Kept explicit so
 * "this hub is compromised" is always evidenced and reversible, rather than a
 * boolean someone can flip.
 */
public class CensorIntegrity {

    public enum State {
        /** Artefact hash and signature match the pin. */
        VERIFIED,
        /** Not yet checked this session. Treated as unverified, not as failed. */
        UNKNOWN,
        /** Artefact missing or unloadable. Often benign: a fresh install. */
        UNAVAILABLE,
        /** Hash differs from the pin. Assume tampering until shown otherwise. */
        MISMATCHED,
        /** A peer advertised a different censor pin during sync. */
        PEER_DIVERGENCE
    }

    private State state;
    private Instant checkedAt;
    private String expectedPinHash;
    private String actualPinHash;

    /** Who or what raised the concern: local check, or a peer endpoint. */
    private String detectedBy;

    /** Human-readable evidence, recorded in the log for later appeal. */
    private String evidence;

    public CensorIntegrity() {
        // TODO: pseudo-code
    }

    /** Whether the hub should restrict members. UNAVAILABLE alone should not. */
    public boolean requiresRestriction() {
        // TODO: pseudo-code
        return false;
    }

    /** Whether Matchmaker may run, given the policy's failure mode. */
    public boolean permitsQuerying(HubPolicy policy) {
        // TODO: pseudo-code
        return false;
    }

    public boolean isVerified() {
        // TODO: pseudo-code
        return false;
    }

    // --- accessors --------------------------------------------------------

    public State getState() {
        return state;
    }

    public Instant getCheckedAt() {
        return checkedAt;
    }

    public String getExpectedPinHash() {
        return expectedPinHash;
    }

    public String getActualPinHash() {
        return actualPinHash;
    }

    public String getEvidence() {
        return evidence;
    }
}
