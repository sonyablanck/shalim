package org.shalim.trust;

import java.time.Instant;

/**
 * What one Matchmaker instance did with one probe.
 *
 * <p>Two of these — one local, one from the peer — are the unit of comparison,
 * and {@link org.shalim.ml.ProbeEngine#score} turns each pair into a
 * {@link DifferenceScore}.
 * Deliberately records more than the decision: a hub that has been hooked to
 * return the right answers from a lookup table produces correct decisions with
 * degenerate confidences, so the shape of the number is evidence even when the
 * number itself agrees.
 *
 * <p>Records no matches and no member names. An audit that returned who a peer
 * hub would have surfaced would be a membership-harvesting tool dressed as a
 * safety check, and would be worth building for that reason alone by anyone
 * hostile. Only the censor's behaviour crosses.
 */
public class ProbeOutcome {

    private String outcomeId;
    private String probeId;

    /** Key fingerprint of the hub that produced this. Never a hub name or id. */
    private String producedByKeyFingerprint;

    private org.shalim.ml.CensorEngine.Decision decision;

    private java.util.List<org.shalim.ml.CensorEngine.Category> categories;

    /** Raw score before thresholding. The most informative field here. */
    private float confidence;

    /**
     * Pin hash the responding instance claims to be running. Compared, but not
     * trusted: a hub willing to lie about its behaviour will lie about this.
     * It is the behaviour that is the measurement.
     */
    private String modelPinHash;

    /**
     * Whether the response came from a degraded path — blocklist fallback, or
     * a matchmaker with no model loaded. Excluded from scoring rather than
     * counted as failure, because {@code UNAVAILABLE} is usually a flat battery.
     */
    private boolean degraded;

    /**
     * Wall-clock time to produce the verdict. Noisy across devices and useless
     * on its own; used only as corroboration when decisions already look
     * synthetic, never as a finding by itself.
     */
    private long elapsedMillis;

    private Instant respondedAt;

    /** Set when the instance did not answer at all. Distinct from answering badly. */
    private String failureReason;

    /**
     * The refusal explanation the asker was shown, when the censor refused.
     * Compared by the prober's encoder, because a retuned hub often changes
     * what it tells people before it changes what it does. Never the
     * Matchmaker's prose, and never any match.
     */
    private String refusalExplanation;

    /** Run this outcome belongs to, for the ledger. */
    private String runId;

    public ProbeOutcome() {
        // TODO: pseudo-code
    }

    public ProbeOutcome(String probeId, String producedByKeyFingerprint,
                        org.shalim.ml.CensorEngine.Decision decision, float confidence) {
        // TODO: pseudo-code
    }

    /** Whether this outcome is usable evidence, or was degraded or absent. */
    public boolean isScoreable() {
        // TODO: pseudo-code
        return false;
    }

    /**
     * Whether the instance did what the corpus says a correct censor does.
     * Scored against the pinned probe intent, not against the other hub — this
     * is what lets an anomaly be attributed rather than merely observed.
     */
    public boolean satisfies(TrustProbe probe) {
        // PSEUDO-CODE
        //
        // Reads the same way for generated probes: intent is inherited from
        // the pinned seed, so "satisfies" still means "did what the corpus says"
        // rather than "did what the generating hub thought".
        //
        // SWITCH probe.intent
        //    SUPPLY_SIGNAL     -> RETURN decision == BLOCK
        //                         // REVIEW is not a pass here. Explicit dealing
        //                         // held for a human is a hub that will deliver
        //                         // it the moment nobody is moderating.
        //    PROTECTED_SPEECH  -> RETURN decision != BLOCK
        //                         // REVIEW is a pass. Held for a human is the
        //                         // designed behaviour for harm-adjacent speech.
        //    BENIGN            -> RETURN decision == ALLOW
        //    NEAR_MISS         -> RETURN true
        //                         // Unscored by design. Near misses sit on the
        //                         // threshold, so two honest instances of the
        //                         // same artefact legitimately disagree. They
        //                         // are in the corpus to measure agreement
        //                         // between instances, not correctness.
        return false;
    }

    // --- accessors --------------------------------------------------------

    public String getOutcomeId() {
        return outcomeId;
    }

    public String getProbeId() {
        return probeId;
    }

    public String getProducedByKeyFingerprint() {
        return producedByKeyFingerprint;
    }

    public org.shalim.ml.CensorEngine.Decision getDecision() {
        return decision;
    }

    public java.util.List<org.shalim.ml.CensorEngine.Category> getCategories() {
        return categories;
    }

    public float getConfidence() {
        return confidence;
    }

    public String getModelPinHash() {
        return modelPinHash;
    }

    public boolean isDegraded() {
        return degraded;
    }

    public long getElapsedMillis() {
        return elapsedMillis;
    }

    public Instant getRespondedAt() {
        return respondedAt;
    }

    public String getFailureReason() {
        return failureReason;
    }

    public String getRefusalExplanation() {
        return refusalExplanation;
    }

    public String getRunId() {
        return runId;
    }
}
