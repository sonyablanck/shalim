package org.shalim.ml;

import java.util.List;

/**
 * One ranked answer to a hub query — a member who can help, or a resource that
 * enables the asker to help themselves.
 */
public class Match {

    public enum Kind {
        MEMBER,
        RESOURCE
    }

    private Kind kind;

    /** userId or resourceId, per {@link #kind}. */
    private String targetId;

    private String displayName;
    private float score;

    /** Which skills caused the match. Shown to the asker so ranking is legible. */
    private List<String> matchedSkillIds;

    /** Short plain-language reason. Screened before display. */
    private String rationale;

    /** True when ranking came from keyword fallback rather than the model. */
    private boolean fromFallback;

    public Match() {
        // TODO: pseudo-code
    }

    // --- accessors --------------------------------------------------------

    public Kind getKind() {
        return kind;
    }

    public String getTargetId() {
        return targetId;
    }

    public String getDisplayName() {
        return displayName;
    }

    public float getScore() {
        return score;
    }

    public List<String> getMatchedSkillIds() {
        return matchedSkillIds;
    }

    public String getRationale() {
        return rationale;
    }

    public boolean isFromFallback() {
        return fromFallback;
    }
}
