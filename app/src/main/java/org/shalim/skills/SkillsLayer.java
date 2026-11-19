package org.shalim.skills;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;
import org.shalim.crypto.Signer;
import org.shalim.ml.CensorEngine;
import org.shalim.ml.MatchmakerEngine;
import org.shalim.ml.Verdict;

/**
 * A hub's index of what it can do, in two deliberately separate halves:
 *
 * <ol>
 *   <li><strong>Resources and hub skills.</strong> The hub's explicit list of
 *       {@link HubResource}s, and the {@link Skill}s the Matchmaker derives
 *       from them. Public: these are what hub search shows.</li>
 *   <li><strong>The member skill index.</strong> {@link UserSkill}s that
 *       current members have presented here, whichever hub they were earned
 *       at. Private: only the Matchmaker reads it, to answer "who can help
 *       me with X?" for members of this hub.</li>
 * </ol>
 *
 * <p>The two never mix. Hub search never sees a user skill, so nothing a
 * stranger reads is traceable to a person. The Matchmaker's people-search
 * never returns a hub skill as though it were a person.
 */
public class SkillsLayer {

    private String hubId;

    /** Explicit, admin-maintained. Set at creation; changed via MANAGE_RESOURCES. */
    private List<HubResource> resources;

    /** Derived from {@link #resources}. Rebuilt whenever resources change. */
    private List<Skill> hubSkills;

    /** User skills imported from current members' presented credentials. */
    private List<MemberSkillEntry> memberIndex;

    /** Interactions awaiting admin verification. Dropped once decided. */
    private List<ResourceInteraction> pendingInteractions;

    /** Cached vectors keyed by id. Invalidated when the model version changes. */
    private String embeddingModelVersion;

    private final Map<String, float[]> embeddings = new HashMap<>();

    /** Link tags already imported, per member, so duplicates are dropped. */
    private final Map<String, Set<String>> importedLinkTags = new HashMap<>();

    /** Resources held for review by the censor; unavailable until cleared. */
    private final Set<String> underReview = new HashSet<>();

    /** Set when resources change; cleared by {@link #deriveHubSkills}. */
    private boolean hubSkillsStale;

    /**
     * One imported user skill, as this hub holds it: the member, the term, the
     * proficiency, the dates. No credential, no ring, no link to where it was
     * earned — those were checked at import and discarded.
     */
    public static class MemberSkillEntry {
        private String userId;
        private String taxonomyTerm;
        private UserSkill.Proficiency proficiency;
        private Instant lastConfirmedAt;
        private boolean offered;

        /** Whether it was earned here. Held for the admin only; never used in ranking. */
        private boolean earnedHere;

        public MemberSkillEntry(String userId, String taxonomyTerm, UserSkill.Proficiency proficiency,
                                Instant lastConfirmedAt, boolean offered, boolean earnedHere) {
            this.userId = userId;
            this.taxonomyTerm = taxonomyTerm;
            this.proficiency = proficiency;
            this.lastConfirmedAt = lastConfirmedAt;
            this.offered = offered;
            this.earnedHere = earnedHere;
        }

        public String getUserId() {
            return userId;
        }

        public String getTaxonomyTerm() {
            return taxonomyTerm;
        }

        public UserSkill.Proficiency getProficiency() {
            return proficiency;
        }

        public Instant getLastConfirmedAt() {
            return lastConfirmedAt;
        }

        public boolean isOffered() {
            return offered;
        }

        public boolean isEarnedHere() {
            return earnedHere;
        }

        String key() {
            return "member|" + userId + "|" + taxonomyTerm;
        }
    }

    /** One search result: a person (by user id) or a resource-backed hub skill (by skill id). */
    public record SearchHit(Kind kind, String id, String term, float score) {
        public enum Kind {
            PERSON,
            RESOURCE
        }
    }

    public SkillsLayer() {
        this.resources = new ArrayList<>();
        this.hubSkills = new ArrayList<>();
        this.memberIndex = new ArrayList<>();
        this.pendingInteractions = new ArrayList<>();
    }

    public SkillsLayer(String hubId) {
        this();
        this.hubId = hubId;
    }

    // --- resources and hub skills -----------------------------------------

    /**
     * Adds a resource after screening its name and description at
     * RESOURCE_DESCRIPTION. Blocked: not added. Held for review: added but
     * unavailable, so it backs no hub skill until a moderator clears it.
     */
    public synchronized Optional<HubResource> addResource(HubResource resource, CensorEngine censor) {
        if (resource == null || censor == null) {
            return Optional.empty();
        }
        Verdict v = censor.assess(join(resource.getName(), resource.getDescription()),
                CensorEngine.Surface.RESOURCE_DESCRIPTION);
        CensorEngine.Decision d = v == null ? CensorEngine.Decision.REVIEW : v.effectiveDecision();
        if (d == CensorEngine.Decision.BLOCK) {
            return Optional.empty();
        }
        if (d == CensorEngine.Decision.REVIEW) {
            resource.setAvailable(false);
            underReview.add(resource.getResourceId());
        }
        resources.add(resource);
        hubSkillsStale = true;
        return Optional.of(resource);
    }

    /** A moderator cleared a resource the censor held. */
    public synchronized boolean clearReview(String resourceId) {
        if (!underReview.remove(resourceId)) {
            return false;
        }
        findResource(resourceId).ifPresent(r -> r.setAvailable(true));
        hubSkillsStale = true;
        return true;
    }

    /**
     * Removes a resource. Earned credentials already issued against it are
     * unaffected: people keep what they learnt. Pending interactions on it are
     * dropped, because there is no longer a skill to verify them against.
     */
    public synchronized boolean removeResource(String resourceId) {
        boolean removed = resources.removeIf(r -> r.getResourceId().equals(resourceId));
        if (removed) {
            underReview.remove(resourceId);
            pendingInteractions.removeIf(i -> resourceId.equals(i.getResourceId()));
            hubSkillsStale = true;
        }
        return removed;
    }

    /**
     * Rebuilds {@link #hubSkills} from {@link #resources}. The only way hub
     * skills are created. The caller logs HUB_SKILLS_DERIVED.
     */
    public synchronized List<Skill> deriveHubSkills(MatchmakerEngine matchmaker, CensorEngine censor) {
        if (matchmaker == null || censor == null) {
            return List.copyOf(hubSkills);
        }
        List<Skill> derived = matchmaker.deriveHubSkills(List.copyOf(resources));
        List<Skill> merged = new ArrayList<>();
        Instant now = Instant.now();
        String pinHash = matchmaker.pin() == null ? null : matchmaker.pin().getArtefactHash();
        for (Skill skill : derived == null ? List.<Skill>of() : derived) {
            if (skill.getLabel() == null || skill.getTaxonomyTerm() == null) {
                continue;
            }
            // Screened at write time: a hub skill is shown to strangers.
            Verdict v = censor.assess(skill.getLabel(), CensorEngine.Surface.HUB_PROFILE);
            if (v == null || v.effectiveDecision() != CensorEngine.Decision.ALLOW) {
                continue;
            }
            // Keep ids stable across re-derivation by taxonomy term: pending
            // interactions reference hub skills, earned credentials do not.
            for (Skill old : hubSkills) {
                if (skill.getTaxonomyTerm().equals(old.getTaxonomyTerm())) {
                    skill.adoptId(old.getSkillId());
                }
            }
            Skill same = merged.stream().filter(m -> m.getTaxonomyTerm().equals(skill.getTaxonomyTerm()))
                    .findFirst().orElse(null);
            if (same != null) {
                List<String> ids = new ArrayList<>(same.getResourceIds());
                for (String id : skill.getResourceIds()) {
                    if (!ids.contains(id)) {
                        ids.add(id);
                    }
                }
                same.setResourceIds(ids);
                continue;
            }
            skill.setCensorVerdictId(v.getVerdictId());
            skill.setDerivedBy(pinHash, now);
            if (skill.getNormalisedText() == null) {
                skill.setNormalisedText(matchmaker.normalise(skill));
            }
            merged.add(skill);
        }
        for (Skill s : merged) {
            s.setOffered(s.isBackedBy(resources));
        }
        for (HubResource r : resources) {
            List<String> ids = new ArrayList<>();
            for (Skill s : merged) {
                if (s.getResourceIds().contains(r.getResourceId())) {
                    ids.add(s.getSkillId());
                }
            }
            r.setSkillIds(ids);
        }
        hubSkills = merged;
        hubSkillsStale = false;
        return List.copyOf(hubSkills);
    }

    public synchronized boolean hasResources() {
        return !resources.isEmpty();
    }

    public synchronized boolean isHubSkillsStale() {
        return hubSkillsStale;
    }

    public synchronized List<HubResource> getResources() {
        return List.copyOf(resources);
    }

    public synchronized List<Skill> getHubSkills() {
        return List.copyOf(hubSkills);
    }

    public synchronized Optional<HubResource> findResource(String resourceId) {
        return resources.stream().filter(r -> r.getResourceId().equals(resourceId)).findFirst();
    }

    // --- earning ----------------------------------------------------------

    /**
     * A member or guest logs use of a resource. The caller has checked
     * RECORD_RESOURCE_USE and logs RESOURCE_INTERACTION_RECORDED, with no
     * resource or user in the detail.
     */
    public synchronized ResourceInteraction recordInteraction(String userKeyFingerprint, String resourceId,
                                                              String note, CensorEngine censor, Instant now) {
        Optional<HubResource> resource = findResource(resourceId);
        if (resource.isEmpty() || !resource.get().isAvailable() || userKeyFingerprint == null) {
            return null;
        }
        ResourceInteraction interaction = new ResourceInteraction(hubId, userKeyFingerprint, resourceId, now);
        if (note != null && !note.isBlank() && censor != null) {
            Verdict v = censor.assess(note, CensorEngine.Surface.USER_SKILL);
            if (v != null && v.effectiveDecision() == CensorEngine.Decision.ALLOW) {
                interaction.setNote(note);
            }
        }
        pendingInteractions.add(interaction);
        return interaction;
    }

    /**
     * An admin verifies an interaction and credentials are issued to the user,
     * one per taxonomy term the resource backs. The caller has checked
     * VERIFY_EARNED_SKILL, and an AUTHENTICATED hub is required: an
     * unauthenticated hub's key is in no ring and cannot sign one.
     *
     * <p>Returns null, leaving the interaction pending, when the hub is not
     * authenticated or no credential scheme is bound. Guests and capped
     * members can still log interactions at a new hub; nothing they earn is
     * lost, it is just not signed yet. Returns an empty list if the interaction
     * is unknown or its resource backs no skill.
     *
     * <p>After this the caller delivers the credentials to the user's device,
     * imports them here if the user is a member who offers them, and logs
     * SKILL_EARNED_VERIFIED with no term and no user. The admin saw who used
     * what; the hub keeps only that a skill was verified.
     */
    public synchronized List<SkillCredential> verifyInteraction(String interactionId, String adminUserId,
                                                                UserSkill.Proficiency proficiency,
                                                                org.shalim.hub.HubStanding standing,
                                                                SkillCredentialScheme scheme,
                                                                List<byte[]> ringIssuerKeys, Signer issuerKey,
                                                                Instant now) {
        if (standing == null || !standing.isAuthenticated() || scheme == null || issuerKey == null
                || ringIssuerKeys == null || ringIssuerKeys.isEmpty()) {
            return null;
        }
        ResourceInteraction interaction = pending(interactionId);
        if (interaction == null) {
            return List.of();
        }
        List<String> terms = new ArrayList<>();
        for (Skill s : hubSkills) {
            if (s.getResourceIds().contains(interaction.getResourceId()) && !terms.contains(s.getTaxonomyTerm())) {
                terms.add(s.getTaxonomyTerm());
            }
        }
        if (terms.isEmpty()) {
            return List.of();
        }
        java.time.LocalDate today = java.time.LocalDate.ofInstant(now, java.time.ZoneOffset.UTC);
        List<SkillCredential> out = new ArrayList<>();
        for (String term : terms) {
            SkillCredential c = scheme.issue(interaction.getUserKeyFingerprint(), term, proficiency, today,
                    ringIssuerKeys, issuerKey);
            if (c != null) {
                out.add(c);
            }
        }
        interaction.decide(ResourceInteraction.Status.VERIFIED, adminUserId, proficiency, now);
        pendingInteractions.remove(interaction);
        return out;
    }

    public synchronized boolean rejectInteraction(String interactionId, String adminUserId, String reason) {
        ResourceInteraction interaction = pending(interactionId);
        if (interaction == null) {
            return false;
        }
        interaction.decide(ResourceInteraction.Status.REJECTED, adminUserId, null, Instant.now());
        pendingInteractions.remove(interaction);
        return true;
    }

    public synchronized List<ResourceInteraction> getPendingInteractions() {
        return List.copyOf(pendingInteractions);
    }

    private ResourceInteraction pending(String interactionId) {
        for (ResourceInteraction i : pendingInteractions) {
            if (i.getInteractionId().equals(interactionId) && i.isPending()) {
                return i;
            }
        }
        return null;
    }

    // --- member skill index -----------------------------------------------

    /**
     * Imports credentials a member chose to present here, earned at this hub
     * or any other. Each must be about this member, verify against a current
     * or recent ring, and not duplicate one already imported. The hub keeps
     * what it needs to match, not the proof: a seized hub device should not
     * hold a pile of ring signatures that a later break of the scheme could
     * de-anonymise. Returns how many were imported; the caller logs the count.
     */
    public synchronized int importPresented(String userId, List<SkillCredential> presented,
                                            List<List<byte[]>> rings, SkillCredentialScheme scheme,
                                            MatchmakerEngine matchmaker, Instant now, boolean earnedHere) {
        int imported = 0;
        Set<String> tags = importedLinkTags.computeIfAbsent(userId, k -> new HashSet<>());
        for (SkillCredential c : presented == null ? List.<SkillCredential>of() : presented) {
            if (c == null || !userId.equals(c.getSubjectKeyFingerprint()) || !c.verify(rings, scheme, now)) {
                continue;
            }
            if (c.getLinkTag() != null && !tags.add(c.getLinkTag())) {
                continue;
            }
            Instant confirmed = c.getIssuedOn() == null ? now
                    : c.getIssuedOn().atStartOfDay(java.time.ZoneOffset.UTC).toInstant();
            MemberSkillEntry existing = null;
            for (MemberSkillEntry e : memberIndex) {
                if (e.userId.equals(userId) && e.taxonomyTerm.equals(c.getTaxonomyTerm())) {
                    existing = e;
                }
            }
            if (existing == null) {
                existing = new MemberSkillEntry(userId, c.getTaxonomyTerm(), c.getProficiency(), confirmed, true,
                        earnedHere);
                memberIndex.add(existing);
            } else {
                if (c.getProficiency() != null && (existing.proficiency == null
                        || c.getProficiency().compareTo(existing.proficiency) > 0)) {
                    existing.proficiency = c.getProficiency();
                }
                if (existing.lastConfirmedAt == null || confirmed.isAfter(existing.lastConfirmedAt)) {
                    existing.lastConfirmedAt = confirmed;
                }
                existing.earnedHere |= earnedHere;
            }
            if (matchmaker != null && matchmaker.pin() != null
                    && java.util.Objects.equals(embeddingModelVersion, matchmaker.pin().getArtefactHash())) {
                embeddings.put(existing.key(), matchmaker.embed(existing.taxonomyTerm));
            }
            imported++;
        }
        return imported;
    }

    /** A member's choice not to be matched on a term here, without removing it. */
    public synchronized boolean setOffered(String userId, String taxonomyTerm, boolean offered) {
        for (MemberSkillEntry e : memberIndex) {
            if (e.userId.equals(userId) && e.taxonomyTerm.equals(taxonomyTerm)) {
                e.offered = offered;
                return true;
            }
        }
        return false;
    }

    /** Drops a departed member's imported skills. Their profile is unaffected. */
    public synchronized int purgeMember(String userId) {
        int before = memberIndex.size();
        for (MemberSkillEntry e : memberIndex) {
            if (e.userId.equals(userId)) {
                embeddings.remove(e.key());
            }
        }
        memberIndex.removeIf(e -> e.userId.equals(userId));
        importedLinkTags.remove(userId);
        pendingInteractions.removeIf(i -> userId.equals(i.getUserKeyFingerprint()));
        return before - memberIndex.size();
    }

    public synchronized List<MemberSkillEntry> offeredMemberSkills() {
        List<MemberSkillEntry> out = new ArrayList<>();
        for (MemberSkillEntry e : memberIndex) {
            if (e.offered) {
                out.add(e);
            }
        }
        return out;
    }

    public synchronized List<MemberSkillEntry> getMemberIndex() {
        return List.copyOf(memberIndex);
    }

    // --- search -----------------------------------------------------------

    private static final Set<String> STOPWORDS = Set.of("a", "an", "and", "are", "can", "do", "for", "help",
            "how", "i", "in", "is", "it", "me", "my", "of", "on", "or", "some", "someone", "the", "to", "want",
            "who", "with", "anyone", "need", "start", "get", "learn", "about", "know", "knows");

    /** Lower case, split on anything that is not a letter or digit, drop stopwords, crude stem. */
    static List<String> tokens(String text) {
        List<String> out = new ArrayList<>();
        if (text == null) {
            return out;
        }
        for (String raw : text.toLowerCase(Locale.ROOT).split("[^\\p{L}\\p{N}]+")) {
            if (raw.length() < 2 || STOPWORDS.contains(raw)) {
                continue;
            }
            out.add(stem(raw));
        }
        return out;
    }

    private static String stem(String w) {
        for (String suffix : new String[] {"ing", "ers", "er", "es", "ed", "s"}) {
            if (w.length() > suffix.length() + 2 && w.endsWith(suffix)) {
                return w.substring(0, w.length() - suffix.length());
            }
        }
        return w;
    }

    private static float overlap(List<String> query, String text) {
        if (query.isEmpty()) {
            return 0;
        }
        Set<String> have = new HashSet<>(tokens(text));
        int hits = 0;
        for (String t : query) {
            if (have.contains(t)) {
                hits++;
            }
        }
        return (float) hits / query.size();
    }

    /**
     * Lexical search over member skills and hub skills. Fallback when no model
     * is loaded. Deliberately dumb and dependency-free: this must work on a
     * dying phone with no model loaded, which is when a hub matters most.
     *
     * @param matchable which members may be surfaced at all; the caller passes
     *                  the roster's rule (not hidden, not restricted, not guests)
     */
    public synchronized List<SearchHit> searchByKeyword(String terms, int limit, Predicate<String> matchable) {
        List<String> q = tokens(terms);
        List<SearchHit> hits = new ArrayList<>();
        for (MemberSkillEntry e : memberIndex) {
            if (!e.offered || (matchable != null && !matchable.test(e.userId))) {
                continue;
            }
            float score = overlap(q, e.taxonomyTerm);
            if (score > 0) {
                hits.add(new SearchHit(SearchHit.Kind.PERSON, e.userId, e.taxonomyTerm, score));
            }
        }
        for (Skill s : hubSkills) {
            if (!s.isOffered()) {
                continue;
            }
            float score = Math.max(overlap(q, s.getLabel()), overlap(q, s.getTaxonomyTerm()));
            if (score > 0) {
                hits.add(new SearchHit(SearchHit.Kind.RESOURCE, s.getSkillId(), s.getTaxonomyTerm(), score));
            }
        }
        return top(hits, limit);
    }

    /** Lexical search with no member filter. Prefer the three-argument form. */
    public List<SearchHit> searchByKeyword(String terms, int limit) {
        return searchByKeyword(terms, limit, null);
    }

    /**
     * Semantic search over cached embeddings of member terms and hub skills.
     * Empty if the cache was built by a different model than the caller's.
     */
    public synchronized List<SearchHit> searchByVector(float[] queryVector, String modelVersion, int limit,
                                                       Predicate<String> matchable) {
        if (queryVector == null || modelVersion == null || !modelVersion.equals(embeddingModelVersion)) {
            return List.of();
        }
        List<SearchHit> people = new ArrayList<>();
        for (MemberSkillEntry e : memberIndex) {
            float[] v = embeddings.get(e.key());
            if (v != null && e.offered && (matchable == null || matchable.test(e.userId))) {
                people.add(new SearchHit(SearchHit.Kind.PERSON, e.userId, e.taxonomyTerm, cosine(queryVector, v)));
            }
        }
        List<SearchHit> resourcesHits = new ArrayList<>();
        for (Skill s : hubSkills) {
            float[] v = embeddings.get("hub|" + s.getSkillId());
            if (v != null && s.isOffered()) {
                resourcesHits.add(new SearchHit(SearchHit.Kind.RESOURCE, s.getSkillId(), s.getTaxonomyTerm(),
                        cosine(queryVector, v)));
            }
        }
        List<SearchHit> out = new ArrayList<>(top(people, limit));
        out.addAll(top(resourcesHits, limit));
        return out;
    }

    private static List<SearchHit> top(List<SearchHit> hits, int limit) {
        hits.sort((a, b) -> Float.compare(b.score(), a.score()));
        return hits.size() > limit ? new ArrayList<>(hits.subList(0, Math.max(0, limit))) : hits;
    }

    static float cosine(float[] a, float[] b) {
        if (a.length != b.length) {
            return 0;
        }
        double dot = 0;
        double na = 0;
        double nb = 0;
        for (int i = 0; i < a.length; i++) {
            dot += a[i] * b[i];
            na += a[i] * a[i];
            nb += b[i] * b[i];
        }
        return na == 0 || nb == 0 ? 0 : (float) (dot / Math.sqrt(na * nb));
    }

    // --- maintenance ------------------------------------------------------

    /** Rebuilds every embedding under the matchmaker's current model. */
    public synchronized int reindex(MatchmakerEngine matchmaker) {
        embeddings.clear();
        if (matchmaker == null || matchmaker.pin() == null) {
            embeddingModelVersion = null;
            return 0;
        }
        embeddingModelVersion = matchmaker.pin().getArtefactHash();
        for (MemberSkillEntry e : memberIndex) {
            embeddings.put(e.key(), matchmaker.embed(e.taxonomyTerm));
        }
        for (Skill s : hubSkills) {
            embeddings.put("hub|" + s.getSkillId(), matchmaker.embed(join(s.getLabel(), s.getTaxonomyTerm())));
            s.setNormalisedText(matchmaker.normalise(s));
        }
        return embeddings.size();
    }

    /**
     * Re-screens everything this layer shows or stores under the current
     * censor: hub skill labels at HUB_PROFILE (dropped unless ALLOW) and
     * interaction notes at USER_SKILL (cleared unless ALLOW). Run after the
     * censor pin changes. Returns how many items were dropped or cleared.
     */
    public synchronized int rescreen(CensorEngine censor) {
        if (censor == null) {
            return 0;
        }
        int changed = 0;
        List<Skill> keep = new ArrayList<>();
        for (Skill s : hubSkills) {
            Verdict v = censor.assess(s.getLabel(), CensorEngine.Surface.HUB_PROFILE);
            if (v != null && v.effectiveDecision() == CensorEngine.Decision.ALLOW) {
                keep.add(s);
            } else {
                embeddings.remove("hub|" + s.getSkillId());
                changed++;
            }
        }
        hubSkills = keep;
        for (ResourceInteraction i : pendingInteractions) {
            if (i.getNote() != null) {
                Verdict v = censor.assess(i.getNote(), CensorEngine.Surface.USER_SKILL);
                if (v == null || v.effectiveDecision() != CensorEngine.Decision.ALLOW) {
                    i.setNote(null);
                    changed++;
                }
            }
        }
        return changed;
    }

    /** Drops pending interactions older than the meeting-request retention window. */
    public synchronized int prune(org.shalim.hub.HubPolicy policy, Instant now) {
        return prune(policy.getMeetingRequestRetentionDays(), now);
    }

    public synchronized int prune(int retentionDays, Instant now) {
        Instant cutoff = now.minus(java.time.Duration.ofDays(retentionDays));
        int before = pendingInteractions.size();
        for (ResourceInteraction i : pendingInteractions) {
            if (i.getOccurredAt() != null && i.getOccurredAt().isBefore(cutoff)) {
                // Not reviewed within the window: dropped, not rejected.
                i.decide(ResourceInteraction.Status.EXPIRED, null, null, now);
            }
        }
        pendingInteractions.removeIf(i -> !i.isPending());
        return before - pendingInteractions.size();
    }

    /** Duress path. */
    public synchronized void wipe() {
        resources.clear();
        hubSkills.clear();
        memberIndex.clear();
        pendingInteractions.clear();
        embeddings.clear();
        importedLinkTags.clear();
        underReview.clear();
    }

    public String getHubId() {
        return hubId;
    }

    public String getEmbeddingModelVersion() {
        return embeddingModelVersion;
    }

    public synchronized Set<String> getUnderReview() {
        return Set.copyOf(underReview);
    }

    /** Restores persisted state. Persistence only; embeddings are rebuilt by reindex(). */
    public synchronized void restore(List<HubResource> resources, List<Skill> hubSkills,
                                     List<MemberSkillEntry> memberIndex, List<ResourceInteraction> pending,
                                     Map<String, Set<String>> linkTags, Set<String> underReview, boolean stale) {
        this.resources = new ArrayList<>(resources);
        this.hubSkills = new ArrayList<>(hubSkills);
        this.memberIndex = new ArrayList<>(memberIndex);
        this.pendingInteractions = new ArrayList<>(pending);
        this.importedLinkTags.clear();
        linkTags.forEach((k, v) -> this.importedLinkTags.put(k, new HashSet<>(v)));
        this.underReview.clear();
        this.underReview.addAll(underReview);
        this.hubSkillsStale = stale;
        this.embeddings.clear();
        this.embeddingModelVersion = null;
    }

    public synchronized Map<String, Set<String>> getImportedLinkTags() {
        Map<String, Set<String>> out = new HashMap<>();
        importedLinkTags.forEach((k, v) -> out.put(k, Set.copyOf(v)));
        return out;
    }

    private static String join(String a, String b) {
        if (a == null) {
            return b == null ? "" : b;
        }
        return b == null ? a : a + "\n" + b;
    }
}
