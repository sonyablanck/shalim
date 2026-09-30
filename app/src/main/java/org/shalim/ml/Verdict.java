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

    public Verdict() {
        // TODO: pseudo-code
    }

    /** Whether this verdict came from the artefact the hub currently pins. */
    public boolean isCurrent(ModelPin currentPin) {
        // TODO: pseudo-code
        return false;
    }

    public boolean isOverridden() {
        // TODO: pseudo-code
        return false;
    }

    /** Decision after any human override is applied. */
    public CensorEngine.Decision effectiveDecision() {
        // TODO: pseudo-code
        return null;
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
