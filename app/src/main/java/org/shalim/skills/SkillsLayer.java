package org.shalim.skills;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

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
    }

    public SkillsLayer() {
        // TODO: pseudo-code
    }

    public SkillsLayer(String hubId) {
        // TODO: pseudo-code
    }

    // --- resources and hub skills -----------------------------------------

    public Optional<HubResource> addResource(HubResource resource, org.shalim.ml.CensorEngine censor) {
        // PSEUDO-CODE
        // verdict = censor.assess(resource.name + description, RESOURCE_DESCRIPTION)
        // IF BLOCK -> RETURN empty; IF REVIEW -> store unavailable until cleared
        // resources.add(resource); mark hub skills for re-derivation
        return Optional.empty();
    }

    public boolean removeResource(String resourceId) {
        // PSEUDO-CODE
        // remove; re-derive hub skills
        // Earned credentials already issued against it are unaffected: people
        // keep what they learnt.
        return false;
    }

    /**
     * Rebuilds {@link #hubSkills} from {@link #resources}. The only way hub
     * skills are created.
     */
    public List<Skill> deriveHubSkills(org.shalim.ml.MatchmakerEngine matchmaker,
                                       org.shalim.ml.CensorEngine censor) {
        // PSEUDO-CODE
        //
        // 1. derived = matchmaker.deriveHubSkills(resources)
        //    // Each with a hub label, a shared taxonomy term and the resource
        //    // ids behind it.
        // 2. FOR EACH skill
        //       verdict = censor.assess(skill.label, HUB_PROFILE)
        //       IF not ALLOW -> drop
        //       // Screened at write time: a hub skill is shown to strangers.
        // 3. merge with existing by taxonomyTerm so skill ids stay stable
        //    across re-derivation (earned credentials do not reference ids,
        //    but pending interactions do)
        // 4. log HUB_SKILLS_DERIVED
        // 5. RETURN hubSkills
        return null;
    }

    public boolean hasResources() {
        // TODO: pseudo-code
        return false;
    }

    public List<HubResource> getResources() {
        return resources;
    }

    public List<Skill> getHubSkills() {
        return hubSkills;
    }

    // --- earning ----------------------------------------------------------

    /** A member or guest logs use of a resource. Requires RECORD_RESOURCE_USE. */
    public ResourceInteraction recordInteraction(String userKeyFingerprint, String resourceId,
                                                 String note, org.shalim.ml.CensorEngine censor,
                                                 Instant now) {
        // PSEUDO-CODE
        // IF resource unknown or unavailable -> RETURN null
        // IF note present -> screen at USER_SKILL; drop note if not ALLOW
        // interaction = PENDING; pendingInteractions.add
        // log RESOURCE_INTERACTION_RECORDED (no resource or user in detail)
        return null;
    }

    /**
     * An admin verifies an interaction and a credential is issued to the
     * user. Requires VERIFY_EARNED_SKILL, and an AUTHENTICATED hub — an
     * unauthenticated hub's key is in no ring and cannot sign one.
     */
    public SkillCredential verifyInteraction(String interactionId, String adminUserId,
                                             UserSkill.Proficiency proficiency,
                                             org.shalim.hub.HubStanding standing,
                                             Instant now) {
        // PSEUDO-CODE
        //
        // 1. IF NOT standing.isAuthenticated()
        //       keep PENDING; tell admin "credentials can be issued once this
        //       hub is authenticated"; RETURN null
        //       // Guests and capped members can still log interactions at a
        //       // new hub; nothing they earn is lost, it is just not signed yet.
        // 2. term = taxonomy term of the hub skill(s) the resource backs
        // 3. credential = ring-sign(subject, term, proficiency, today)
        //    over the ring of listed issuer keys
        // 4. deliver to the user's device; user's SkillProfile.store()
        // 5. IF the user is a current member -> importPresented([credential])
        //    so it is matchable here at once, if they chose to offer it
        // 6. drop the interaction; log SKILL_EARNED_VERIFIED (no term, no user)
        //    // The admin saw who used what. The hub keeps only that a skill was
        //    // verified. Admins are the weakest point in an infiltrated hub,
        //    // and this is one more thing they see — see README.
        return null;
    }

    public boolean rejectInteraction(String interactionId, String adminUserId, String reason) {
        // TODO: pseudo-code
        return false;
    }

    // --- member skill index -----------------------------------------------

    /**
     * Imports credentials a member chose to present here, earned at this hub
     * or any other.
     */
    public int importPresented(String userId, List<SkillCredential> presented,
                               List<byte[]> ringIssuerKeys, org.shalim.ml.MatchmakerEngine matchmaker,
                               Instant now) {
        // PSEUDO-CODE
        // FOR EACH credential
        //    IF credential.subject != userId's key -> skip
        //    IF NOT credential.verify(ringIssuerKeys, now) -> skip
        //    IF linkTag already imported -> skip (duplicate)
        //    upsert MemberSkillEntry(userId, term, proficiency, issuedOn)
        //    cache embedding of term under current model version
        //    DISCARD the credential
        //    // The hub keeps what it needs to match, not the proof. A seized
        //    // hub device should not hold a pile of ring signatures that a
        //    // later break of the scheme could de-anonymise.
        // log SKILL_CREDENTIAL_IMPORTED (count only)
        return 0;
    }

    /** Drops a departed member's imported skills. Their profile is unaffected. */
    public int purgeMember(String userId) {
        // TODO: pseudo-code
        return 0;
    }

    public List<MemberSkillEntry> offeredMemberSkills() {
        // TODO: pseudo-code
        return null;
    }

    // --- search -----------------------------------------------------------

    /** Lexical search over member skills and hub skills. Fallback when no model is loaded. */
    public List<Object> searchByKeyword(String terms, int limit) {
        // PSEUDO-CODE
        // tokens = normalise and stem terms, drop stopwords
        // score member entries by taxonomyTerm; score hub skills by label + term
        // RETURN top `limit` above zero, each tagged PERSON or RESOURCE
        //    // Deliberately dumb and dependency-free: this must work on a
        //    // dying phone with no model loaded, which is when a hub matters most.
        return null;
    }

    /** Semantic search over cached embeddings of member terms and hub skills. */
    public List<Object> searchByVector(float[] queryVector, int limit) {
        // PSEUDO-CODE
        // IF embeddingModelVersion != current matchmaker pin -> RETURN empty
        // cosine over member entries and hub skills separately
        // RETURN top `limit` of each, tagged
        return null;
    }

    // --- maintenance ------------------------------------------------------

    public int reindex(org.shalim.ml.MatchmakerEngine matchmaker) {
        // TODO: pseudo-code
        return 0;
    }

    public int rescreen(org.shalim.ml.CensorEngine censor) {
        // TODO: pseudo-code
        return 0;
    }

    /** Drops pending interactions older than the meeting-request retention window. */
    public int prune(org.shalim.hub.HubPolicy policy, Instant now) {
        // TODO: pseudo-code
        return 0;
    }

    public String getHubId() {
        return hubId;
    }

    public String getEmbeddingModelVersion() {
        return embeddingModelVersion;
    }
}
