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
        this.state = State.UNKNOWN;
    }

    private CensorIntegrity(State state, Instant checkedAt, String expected, String actual, String detectedBy,
                            String evidence) {
        this.state = state;
        this.checkedAt = checkedAt;
        this.expectedPinHash = expected;
        this.actualPinHash = actual;
        this.detectedBy = detectedBy;
        this.evidence = evidence;
    }

    /**
     * The local check, run at startup and whenever the artefact changes: is
     * the censor loaded, does it hash to its pin, and is that pin the one the
     * policy requires?
     */
    public static CensorIntegrity checkLocal(org.shalim.ml.CensorEngine censor, HubPolicy policy, Instant now) {
        String required = policy == null ? null : policy.getRequiredCensorPinHash();
        if (censor == null || !censor.isLoaded() || censor.pin() == null) {
            return new CensorIntegrity(State.UNAVAILABLE, now, required, null, "local",
                    "No censor artefact is loaded.");
        }
        String actual = censor.pin().getArtefactHash();
        if (!censor.isVerified()) {
            return new CensorIntegrity(State.MISMATCHED, now, required, actual, "local",
                    "The loaded censor artefact does not match its own pinned hash.");
        }
        if (required != null && !org.shalim.crypto.Bytes.equalHex(required, actual)) {
            return new CensorIntegrity(State.MISMATCHED, now, required, actual, "local",
                    "The loaded censor is not the one this hub's policy requires.");
        }
        return new CensorIntegrity(State.VERIFIED, now, required, actual, "local", null);
    }

    /** A replica advertised a different censor pin during sync. */
    public static CensorIntegrity peerDivergence(String expected, String peerPin, String peerEndpointId, Instant now) {
        return new CensorIntegrity(State.PEER_DIVERGENCE, now, expected, peerPin, peerEndpointId,
                "A replica of this hub advertised a different censor during sync.");
    }

    /**
     * Whether the hub should restrict members. UNAVAILABLE alone should not:
     * a member who has simply not downloaded the model yet is not suspect.
     * PEER_DIVERGENCE does: a replica is running something else, and until
     * someone looks it is not known which side was tampered with.
     */
    public boolean requiresRestriction() {
        return state == State.MISMATCHED || state == State.PEER_DIVERGENCE;
    }

    /**
     * Whether Matchmaker may run, given the policy's failure mode. Never
     * "carry on unscreened": every mode other than VERIFIED either stops
     * queries or routes them somewhere a human or a blocklist sees them first.
     */
    public boolean permitsQuerying(HubPolicy policy) {
        if (state == State.VERIFIED) {
            return true;
        }
        if (requiresRestriction()) {
            return false; // tampering is not a failure mode to work around
        }
        HubPolicy.CensorFailureMode mode = policy == null ? HubPolicy.CensorFailureMode.DISABLE_QUERIES
                : policy.getCensorFailureMode();
        return mode == HubPolicy.CensorFailureMode.QUEUE_FOR_REVIEW
                || mode == HubPolicy.CensorFailureMode.BLOCKLIST_ONLY;
    }

    public boolean isVerified() {
        return state == State.VERIFIED;
    }

    public String getDetectedBy() {
        return detectedBy;
    }

    /** Restores persisted state. Persistence only. */
    public static CensorIntegrity restore(State state, Instant checkedAt, String expected, String actual,
                                          String detectedBy, String evidence) {
        return new CensorIntegrity(state, checkedAt, expected, actual, detectedBy, evidence);
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
