package org.shalim.ml;

import java.util.List;

/**
 * Screens free text before it enters the skills layer or reaches another
 * member. Users never call this directly and never see it in the UI; it sits
 * behind {@link MatchmakerEngine} and the skills layer.
 *
 * <p>Deliberately an interface with a pinned artefact rather than a shared
 * remote service. "Every hub runs the same instance" would mean a single
 * chokepoint that stops working in a blackout and that whoever controls it can
 * be compelled to alter. Instead every hub runs the same <em>artefact</em>,
 * identified by {@link ModelPin} hash, locally and offline. Identical
 * behaviour, no single point of coercion.
 */
public interface CensorEngine {

    /** Where the text came from. Thresholds vary by surface. */
    enum Surface {
        USER_SKILL,
        RESOURCE_DESCRIPTION,
        HUB_QUERY,
        MEETING_REQUEST,
        HUB_PROFILE,
        GENERATED_OUTPUT
    }

    /**
     * Harm categories. Scoped tightly to the things Shalim must not be used
     * for, rather than general "toxicity" — a hub discussing overdose response,
     * abortion access, or border crossings is doing exactly its job, and a
     * generic toxicity classifier would wrongly silence all three.
     */
    enum Category {
        CONTROLLED_SUBSTANCE_SUPPLY,
        WEAPONS_SUPPLY,
        HUMAN_TRAFFICKING,
        CHILD_SAFEGUARDING,
        VIOLENT_EXTREMISM
    }

    enum Decision {
        ALLOW,
        /** Held for human review. The default when the model is unsure. */
        REVIEW,
        BLOCK
    }

    /** Classifies one piece of text. Must not throw; degrade to REVIEW instead. */
    Verdict assess(String text, Surface surface);

    List<Verdict> assessAll(List<String> texts, Surface surface);

    /** Identifies the exact artefact in use, so peers can detect divergence. */
    ModelPin pin();

    /** True when the loaded artefact matches its expected hash. */
    boolean isVerified();

    void load() throws ModelUnavailableException;

    void unload();

    boolean isLoaded();
}
