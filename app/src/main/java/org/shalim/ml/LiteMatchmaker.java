package org.shalim.ml;

import java.util.List;
import org.shalim.query.HubQuery;
import org.shalim.query.QueryResult;
import org.shalim.skills.Skill;
import org.shalim.skills.SkillsLayer;

/**
 * Matchmaker for devices that cannot hold a 1.5B model — a small embedding
 * model for ranking, template phrasing instead of generation, and keyword
 * search if even that is unavailable.
 *
 * <p>Exists because a hub is most needed when conditions are worst. An old
 * phone on a dying battery during a blackout must still be able to answer "who
 * near me can purify water?", and it will not be running Qwen to do it.
 * Results are marked degraded so nobody mistakes a keyword hit for a judgement.
 */
public class LiteMatchmaker implements MatchmakerEngine {

    private ModelPin embeddingPin;
    private CensorEngine censor;
    private boolean loaded;

    public LiteMatchmaker() {
        // TODO: pseudo-code
    }

    public LiteMatchmaker(ModelPin embeddingPin, CensorEngine censor) {
        // TODO: pseudo-code
    }

    @Override
    public String normalise(Skill skill) {
        // TODO: pseudo-code
        return null;
    }

    @Override
    public String summariseMember(String userId, SkillsLayer layer) {
        // TODO: pseudo-code
        return null;
    }

    @Override
    public String summariseHub(SkillsLayer layer) {
        // TODO: pseudo-code
        return null;
    }

    @Override
    public List<Skill> deriveHubSkills(List<org.shalim.skills.HubResource> resources) {
        // PSEUDO-CODE
        // FOR EACH resource -> candidate competences from name, kind, description
        //    // QwenMatchmaker generates; LiteMatchmaker maps resource kind and
        //    // description keywords onto the taxonomy directly.
        // map each candidate to its nearest shared taxonomy term
        //    // The term, not the label, is what earned credentials carry.
        // merge candidates with the same term across resources
        // RETURN skills with origin RESOURCE (or INFERRED where several
        //        resources combine), each listing its resource ids
        return null;
    }

    @Override
    public float[] embed(String text) {
        // TODO: pseudo-code
        return null;
    }

    @Override
    public QueryResult answer(HubQuery query, SkillsLayer layer) {
        // PSEUDO-CODE
        //
        // Same contract as QwenMatchmaker, minus generation. The prose is a
        // template, so it can never hallucinate — the honest trade for running
        // on a device that cannot hold a 1.5B model.
        //
        // 1. IF query.verdictId is null -> screen as in QwenMatchmaker
        // 2. matches = rank(query.question, layer, query.maxMatches)
        // 3. answer = template: "N members and M resources match ‘<question>’."
        //    // Fixed string, so no output screening is needed beyond the
        //    // already-screened question.
        // 4. RETURN QueryResult.ranked(query, matches, degraded = usedKeywords)
        return null;
    }

    @Override
    public List<Match> rank(String question, SkillsLayer layer, int limit) {
        // PSEUDO-CODE
        // IF loaded AND layer.embeddingModelVersion matches pin
        //    candidates = layer.searchByVector(embed(question), limit * 5)
        //    fromFallback = false
        // ELSE
        //    RETURN keywordFallback(question, layer, limit)
        //
        // Apply the SAME filter, score, group and threshold steps as
        // QwenMatchmaker.rank — visibility and restriction rules must not vary
        // by device capability, or a weaker phone becomes a way to see members
        // who chose to be hidden.
        return null;
    }

    /** Last-resort lexical matching. Always marks results degraded. */
    public List<Match> keywordFallback(String question, SkillsLayer layer, int limit) {
        // PSEUDO-CODE
        // candidates = layer.searchByKeyword(question, limit * 5)
        // apply the identical visibility and restriction filters
        // RETURN top `limit`, every Match with fromFallback = true
        //    // Surfaced in the UI as "keyword match" so nobody reads a literal
        //    // word hit as a judgement about who can help.
        return null;
    }

    @Override
    public ModelPin pin() {
        // TODO: pseudo-code
        return embeddingPin;
    }

    @Override
    public void load() throws ModelUnavailableException {
        // TODO: pseudo-code
    }

    @Override
    public void unload() {
        // TODO: pseudo-code
    }

    @Override
    public boolean isLoaded() {
        // TODO: pseudo-code
        return loaded;
    }

    @Override
    public CensorEngine censor() {
        // TODO: pseudo-code
        return censor;
    }
}
