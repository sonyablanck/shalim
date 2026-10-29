package org.shalim.trust;

/**
 * How far one peer's handling of one probe diverged from this hub's, and from
 * what the probe expected. Produced by {@link org.shalim.ml.ProbeEngine#score}.
 *
 * <p>Two readings are kept apart on purpose:
 * <ul>
 *   <li>{@link #magnitude} — a 0..1 blend of decision, category, confidence
 *       and refusal-wording divergence. Useful to show an admin; useless as a
 *       verdict, because it is symmetric and cannot say which hub moved.</li>
 *   <li>{@link #peerMetExpectation} and {@link #localMetExpectation} —
 *       whether each side did what the pinned seed says a correct censor does.
 *       This is what attribution and revocation read.</li>
 * </ul>
 *
 * <p>A high magnitude with both sides meeting expectation is two honest hubs
 * disagreeing on confidence, and means nothing. A high magnitude where only
 * the local side missed is this hub's fault. Only a peer miss that the local
 * side did not share counts against the peer.
 */
public class DifferenceScore {

    /** Which evidence stream produced the score. */
    public enum Source {
        /** A generated PASS-side probe, scored against the corpus seed. */
        SYNTHETIC,
        /**
         * A prober's own real question, scored against their device's pinned
         * verdict. Corroborating only: the text is not retained, so it cannot
         * be produced at an appeal.
         */
        ORGANIC
    }

    private Source source;

    private String probeId;
    private String runId;

    /** Peer key fingerprint. Never a hub id. */
    private String peerKeyFingerprint;

    private TrustProbe.Intent intent;

    /** 0 = identical behaviour, 1 = opposite decisions with nothing in common. */
    private float magnitude;

    /** Component parts, kept for the admin and for appeal. */
    private boolean decisionDiffers;
    private float categoryDivergence;
    private float confidenceDivergence;
    /** NaN when neither side refused, so there was no wording to compare. */
    private float wordingDivergence;

    private boolean peerMetExpectation;
    private boolean localMetExpectation;

    /** False when either outcome was degraded or missing. Excluded from all windows. */
    private boolean scoreable;

    public DifferenceScore() {
        // TODO: pseudo-code
    }

    public static DifferenceScore unscoreable(String probeId, String peerKeyFingerprint) {
        // TODO: pseudo-code
        return null;
    }

    /** Which side the evidence in this one probe points at. */
    public AuditAnomaly.Attribution attribution() {
        // PSEUDO-CODE
        // IF NOT scoreable OR intent == NEAR_MISS -> UNDETERMINED
        // IF NOT peerMet AND localMet  -> PEER
        // IF peerMet AND NOT localMet  -> LOCAL
        // IF NOT peerMet AND NOT localMet -> BOTH
        // RETURN UNDETERMINED
        return null;
    }

    /**
     * Under-blocking by the peer on this probe. Kept for local self-test
     * scores; never true for a peer, because no SUPPLY_SIGNAL probe is sent to
     * one. Under-blocking by peers is found by replay instead.
     */
    public boolean isPeerUnderBlock() {
        // PSEUDO-CODE
        // RETURN scoreable AND intent == SUPPLY_SIGNAL AND NOT peerMet AND localMet
        return false;
    }

    /** Over-blocking by the peer on this probe: a PASS probe the peer blocked. */
    public boolean isPeerOverBlock() {
        // PSEUDO-CODE
        // RETURN scoreable AND intent IN (BENIGN, PROTECTED_SPEECH)
        //        AND NOT peerMet AND localMet
        return false;
    }

    // --- accessors --------------------------------------------------------

    public Source getSource() {
        return source;
    }

    public String getProbeId() {
        return probeId;
    }

    public String getRunId() {
        return runId;
    }

    public String getPeerKeyFingerprint() {
        return peerKeyFingerprint;
    }

    public TrustProbe.Intent getIntent() {
        return intent;
    }

    public float getMagnitude() {
        return magnitude;
    }

    public boolean isDecisionDiffers() {
        return decisionDiffers;
    }

    public float getCategoryDivergence() {
        return categoryDivergence;
    }

    public float getConfidenceDivergence() {
        return confidenceDivergence;
    }

    public float getWordingDivergence() {
        return wordingDivergence;
    }

    public boolean isPeerMetExpectation() {
        return peerMetExpectation;
    }

    public boolean isLocalMetExpectation() {
        return localMetExpectation;
    }

    public boolean isScoreable() {
        return scoreable;
    }
}
