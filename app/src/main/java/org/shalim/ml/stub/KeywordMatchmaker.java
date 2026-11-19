package org.shalim.ml.stub;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.shalim.crypto.Canonical;
import org.shalim.crypto.Hashing;
import org.shalim.ml.CensorEngine;
import org.shalim.ml.Match;
import org.shalim.ml.MatchmakerEngine;
import org.shalim.ml.ModelPin;
import org.shalim.ml.ModelUnavailableException;
import org.shalim.query.HubQuery;
import org.shalim.query.QueryResult;
import org.shalim.skills.HubResource;
import org.shalim.skills.Skill;
import org.shalim.skills.SkillsLayer;

/**
 * A stand-in for QwenMatchmaker with deterministic, model-free behaviour:
 * <ul>
 *   <li>hub skills are derived from a keyword-to-taxonomy table: a resource
 *       whose name or description contains a keyword backs that term;</li>
 *   <li>ranking is {@link SkillsLayer#searchByKeyword}, the same fallback a
 *       real hub uses when no model is loaded, so results are marked
 *       degraded;</li>
 *   <li>embeddings are a 64-dimension hashing trick, enough to exercise the
 *       vector path and its model-version checks.</li>
 * </ul>
 * There is no generated prose. Like {@link FixedCensor}, it exists so the hub
 * core can be built against known outputs before real models arrive.
 */
public final class KeywordMatchmaker implements MatchmakerEngine {

    private final CensorEngine censor;
    private final Map<String, String> taxonomy;
    private final ModelPin pin;
    private boolean loaded;

    /** @param taxonomy keyword (lower case) to shared taxonomy term */
    public KeywordMatchmaker(CensorEngine censor, Map<String, String> taxonomy) {
        if (censor == null) {
            throw new IllegalArgumentException("a matchmaker is always constructed with a censor");
        }
        this.censor = censor;
        this.taxonomy = new LinkedHashMap<>();
        taxonomy.forEach((k, v) -> this.taxonomy.put(k.toLowerCase(Locale.ROOT), v));
        List<String> rows = new ArrayList<>();
        this.taxonomy.forEach((k, v) -> rows.add(k + "=" + v));
        this.pin = new ModelPin(ModelPin.Purpose.MATCHMAKER, "keyword-matchmaker-stub", "0",
                Canonical.of("shalim.stub.matchmaker.v1").strings(rows).digestHex(), "jvm", "none");
    }

    @Override
    public String normalise(Skill skill) {
        return skill.getTaxonomyTerm() == null ? null : skill.getTaxonomyTerm().toLowerCase(Locale.ROOT);
    }

    @Override
    public String summariseMember(String userId, SkillsLayer layer) {
        List<String> terms = new ArrayList<>();
        for (SkillsLayer.MemberSkillEntry e : layer.offeredMemberSkills()) {
            if (e.getUserId().equals(userId)) {
                terms.add(e.getTaxonomyTerm());
            }
        }
        return terms.isEmpty() ? null : "Can help with " + String.join(", ", terms) + ".";
    }

    @Override
    public String summariseHub(SkillsLayer layer) {
        List<String> labels = new ArrayList<>();
        for (Skill s : layer.getHubSkills()) {
            if (s.isOffered()) {
                labels.add(s.getLabel());
            }
        }
        return labels.isEmpty() ? null : "Resources for " + String.join(", ", labels) + ".";
    }

    @Override
    public List<Skill> deriveHubSkills(List<HubResource> resources) {
        Map<String, Skill> byTerm = new LinkedHashMap<>();
        for (HubResource r : resources) {
            String text = ((r.getName() == null ? "" : r.getName()) + " "
                    + (r.getDescription() == null ? "" : r.getDescription())).toLowerCase(Locale.ROOT);
            for (Map.Entry<String, String> e : taxonomy.entrySet()) {
                if (text.contains(e.getKey())) {
                    Skill s = byTerm.get(e.getValue());
                    if (s == null) {
                        s = new Skill(r.getHubId(), Skill.Origin.RESOURCE, List.of(r.getResourceId()),
                                capitalise(e.getValue()));
                        s.setTaxonomyTerm(e.getValue());
                        byTerm.put(e.getValue(), s);
                    } else if (!s.getResourceIds().contains(r.getResourceId())) {
                        List<String> ids = new ArrayList<>(s.getResourceIds());
                        ids.add(r.getResourceId());
                        s.setResourceIds(ids);
                    }
                }
            }
        }
        return new ArrayList<>(byTerm.values());
    }

    private static String capitalise(String s) {
        return s.isEmpty() ? s : Character.toUpperCase(s.charAt(0)) + s.substring(1);
    }

    @Override
    public float[] embed(String text) {
        float[] v = new float[64];
        if (text == null) {
            return v;
        }
        for (String token : text.toLowerCase(Locale.ROOT).split("[^\\p{L}\\p{N}]+")) {
            if (token.isEmpty()) {
                continue;
            }
            byte[] h = Hashing.sha256(token.getBytes(StandardCharsets.UTF_8));
            v[(h[0] & 0xff) % 64] += (h[1] & 1) == 0 ? 1f : -1f;
        }
        return v;
    }

    @Override
    public QueryResult answer(HubQuery query, SkillsLayer layer) {
        List<Match> matches = rank(query.getQuestion(), layer, query.getMaxMatches());
        return QueryResult.answered(query.getQueryId(), matches, null, true, matches.size());
    }

    @Override
    public List<Match> rank(String question, SkillsLayer layer, int limit) {
        List<Match> out = new ArrayList<>();
        for (SkillsLayer.SearchHit hit : layer.searchByKeyword(question, limit)) {
            Match.Kind kind = hit.kind() == SkillsLayer.SearchHit.Kind.PERSON ? Match.Kind.MEMBER : Match.Kind.RESOURCE;
            out.add(new Match(kind, hit.id(), null, hit.score(), List.of(hit.term()),
                    "Matched on " + hit.term() + ".", true));
        }
        return out;
    }

    @Override
    public ModelPin pin() {
        return pin;
    }

    @Override
    public void load() throws ModelUnavailableException {
        loaded = true;
    }

    @Override
    public void unload() {
        loaded = false;
    }

    @Override
    public boolean isLoaded() {
        return loaded;
    }

    @Override
    public CensorEngine censor() {
        return censor;
    }
}
