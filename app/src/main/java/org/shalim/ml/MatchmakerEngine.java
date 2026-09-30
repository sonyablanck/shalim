package org.shalim.ml;

import java.util.List;
import org.shalim.query.HubQuery;
import org.shalim.query.QueryResult;
import org.shalim.skills.Skill;
import org.shalim.skills.SkillsLayer;

/**
 * Summarises skills and answers "who can help me with X?" within one hub.
 *
 * <p>An interface because implementations legitimately vary per hub — a
 * server-backed hub may run the full Qwen2.5-1.5B while a phone-only hub falls
 * back to embeddings plus keyword ranking. What must <em>not</em> vary is the
 * censor, which is why every implementation is constructed with a
 * {@link CensorEngine} and is expected to screen both the incoming question
 * and its own generated output.
 */
public interface MatchmakerEngine {

    /** Condenses raw skill text into comparable phrasing for ranking. */
    String normalise(Skill skill);

    /** One-line summary of what a member offers, built from their skills. */
    String summariseMember(String userId, SkillsLayer layer);

    /**
     * Hub-level summary over hub skills only — never member skills. What hub
     * search shows.
     */
    String summariseHub(SkillsLayer layer);

    /**
     * Derives hub skills from the hub's explicit resource list. Each carries a
     * hub-facing label, a term from the shared skill taxonomy, and the
     * resource ids behind it. The only source of hub skills.
     */
    List<Skill> deriveHubSkills(List<org.shalim.skills.HubResource> resources);

    /** Vector for ranking. May be served by a smaller model than generation. */
    float[] embed(String text);

    /**
     * Answers a hub query. People are matched on the user skills members have
     * presented here, wherever those were earned; resources are matched on hub
     * skills. Implementations must screen the question before retrieval and
     * screen generated text before returning it, must exclude hidden,
     * restricted and guest members, and must set
     * {@link QueryResult#isDegraded()} when falling back.
     */
    QueryResult answer(HubQuery query, SkillsLayer layer);

    /** Ranking without generation, for low-end devices and constrained transports. */
    List<Match> rank(String question, SkillsLayer layer, int limit);

    ModelPin pin();

    void load() throws ModelUnavailableException;

    void unload();

    boolean isLoaded();

    /** The censor this engine screens through. Never null. */
    CensorEngine censor();
}
