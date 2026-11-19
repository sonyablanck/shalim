package org.shalim.ml;

import java.time.Instant;
import java.util.List;

/**
 * Immutable output of a {@link CensorEngine} assessment. Stored so text is not
 * re-scored on every query, and logged so a decision can always be explained
 * and contested.
 */
public class Verdict {

    private String verdictId;
    private CensorEngine.Decision decision;
    private List<CensorEngine.Category> categories;
    private float confidence;

    /** Hash of the artefact that produced this, so stale verdicts are detectable. */
    private String modelPinHash;

    private Instant assessedAt;

    /** Set when a human overturned the model. The human's decision wins. */
    private String overriddenByUserId;
    private String overrideJustification;
    private CensorEngine.Decision overriddenDecision;

    /**
     * An unscreened placeholder. Its decision is REVIEW, never ALLOW: a
     * verdict nobody produced must not clear anything.
     */
    public Verdict() {
        this.verdictId = org.shalim.crypto.Bytes.randomId();
        this.decision = CensorEngine.Decision.REVIEW;
        this.categories = List.of();
        this.assessedAt = Instant.now();
    }

    /**
     * A verdict as the censor produced it. Added with the censor decision log,
     * which commits to exactly these fields.
     */
    public Verdict(CensorEngine.Decision decision, List<CensorEngine.Category> categories,
                   float confidence, String modelPinHash, Instant assessedAt) {
        this.verdictId = org.shalim.crypto.Bytes.randomId();
        this.decision = decision;
        this.categories = categories == null ? List.of() : List.copyOf(categories);
        this.confidence = confidence;
        this.modelPinHash = modelPinHash;
        this.assessedAt = assessedAt;
    }

    /** Whether this verdict came from the artefact the hub currently pins. */
    public boolean isCurrent(ModelPin currentPin) {
        return currentPin != null && modelPinHash != null && currentPin.getArtefactHash() != null
                && org.shalim.crypto.Bytes.equalHex(modelPinHash, currentPin.getArtefactHash());
    }

    public boolean isOverridden() {
        return overriddenDecision != null;
    }

    /** Decision after any human override is applied. */
    public CensorEngine.Decision effectiveDecision() {
        return overriddenDecision != null ? overriddenDecision : decision;
    }

    /**
     * A moderator's decision on a held or contested verdict. Verdicts are
     * immutable, so this returns a copy with the same id and the override
     * recorded; the model's own decision is kept beside it, for the log.
     */
    public Verdict overriddenBy(String moderatorUserId, CensorEngine.Decision decision, String justification) {
        if (moderatorUserId == null || decision == null || justification == null || justification.isBlank()) {
            throw new IllegalArgumentException("an override names its moderator, decision and reason");
        }
        Verdict v = new Verdict(this.decision, this.categories, this.confidence, this.modelPinHash, this.assessedAt);
        v.verdictId = this.verdictId;
        v.overriddenDecision = decision;
        v.overriddenByUserId = moderatorUserId;
        v.overrideJustification = justification;
        return v;
    }

    public String getOverriddenByUserId() {
        return overriddenByUserId;
    }

    public String getOverrideJustification() {
        return overrideJustification;
    }

    // --- accessors --------------------------------------------------------

    public String getVerdictId() {
        return verdictId;
    }

    public CensorEngine.Decision getDecision() {
        return decision;
    }

    public List<CensorEngine.Category> getCategories() {
        return categories;
    }

    public float getConfidence() {
        return confidence;
    }

    public String getModelPinHash() {
        return modelPinHash;
    }

    public Instant getAssessedAt() {
        return assessedAt;
    }
}
