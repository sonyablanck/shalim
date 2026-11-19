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
        this.outcomeId = org.shalim.crypto.Bytes.randomId();
        this.categories = java.util.List.of();
    }

    public ProbeOutcome(String probeId, String producedByKeyFingerprint,
                        org.shalim.ml.CensorEngine.Decision decision, float confidence) {
        this();
        this.probeId = probeId;
        this.producedByKeyFingerprint = producedByKeyFingerprint;
        this.decision = decision;
        this.confidence = confidence;
    }

    /** Whether this outcome is usable evidence, or was degraded or absent. */
    public boolean isScoreable() {
        return !degraded && failureReason == null && decision != null;
    }

    /**
     * Whether the instance did what the corpus says a correct censor does.
     * Scored against the pinned probe intent, not against the other hub — this
     * is what lets an anomaly be attributed rather than merely observed.
     */
    public boolean satisfies(TrustProbe probe) {
        if (decision == null) {
            return false;
        }
        return switch (probe.getIntent()) {
            // REVIEW is not a pass here. Explicit dealing held for a human is a
            // hub that will deliver it the moment nobody is moderating.
            case SUPPLY_SIGNAL -> decision == org.shalim.ml.CensorEngine.Decision.BLOCK;
            // REVIEW is a pass: held for a human is the designed behaviour for
            // harm-adjacent speech.
            case PROTECTED_SPEECH -> decision != org.shalim.ml.CensorEngine.Decision.BLOCK;
            case BENIGN -> decision == org.shalim.ml.CensorEngine.Decision.ALLOW;
            // Unscored by design: near misses sit on the threshold.
            case NEAR_MISS -> true;
        };
    }

    /** A local leg: this hub's own censor's verdict on the probe text. */
    public static ProbeOutcome fromVerdict(String probeId, String producedBy, org.shalim.ml.Verdict v,
                                           boolean verified) {
        ProbeOutcome o = new ProbeOutcome(probeId, producedBy, v.getDecision(), v.getConfidence());
        o.categories = v.getCategories();
        o.modelPinHash = v.getModelPinHash();
        o.degraded = !verified;
        o.respondedAt = v.getAssessedAt();
        return o;
    }

    /**
     * A peer leg, from what the asker could see: answered means ALLOW, held
     * means REVIEW, refused by the censor means BLOCK. A refusal for any other
     * reason (rate limit, hub unavailable) is not a censor decision at all and
     * is recorded as a failure, never scored. Matches are never read.
     */
    public static ProbeOutcome fromQueryResult(String probeId, String producedBy,
                                               org.shalim.query.QueryResult r, java.time.Instant now) {
        ProbeOutcome o = new ProbeOutcome();
        o.probeId = probeId;
        o.producedByKeyFingerprint = producedBy;
        o.respondedAt = now;
        if (r == null) {
            o.failureReason = "no answer";
            return o;
        }
        if (r.isHeld()) {
            o.decision = org.shalim.ml.CensorEngine.Decision.REVIEW;
        } else if (r.wasBlocked()) {
            if (r.getCensorReceipt() == null) {
                o.failureReason = "refused before screening";
                return o;
            }
            o.decision = org.shalim.ml.CensorEngine.Decision.BLOCK;
            o.refusalExplanation = r.getBlockedReason();
        } else {
            o.decision = org.shalim.ml.CensorEngine.Decision.ALLOW;
            o.degraded = r.isDegraded();
        }
        return o;
    }

    /** No answer at all. Distinct from answering badly. */
    public static ProbeOutcome failed(String probeId, String producedBy, String reason) {
        ProbeOutcome o = new ProbeOutcome();
        o.probeId = probeId;
        o.producedByKeyFingerprint = producedBy;
        o.failureReason = reason == null ? "failed" : reason;
        return o;
    }

    void setRunId(String runId) {
        this.runId = runId;
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
