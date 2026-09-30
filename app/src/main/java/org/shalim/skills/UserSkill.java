package org.shalim.skills;

import java.time.Instant;

/**
 * A skill a person has earned by using a hub's resources, verified by that
 * hub's admin, and carried on the person's own device in their
 * {@link SkillProfile}.
 *
 * <p>User skills are what the Matchmaker searches when a member asks "who can
 * help me with X?" — in whichever hub the question is asked, and regardless of
 * which hub the skill was earned at. Someone who learnt to use a lathe at the
 * makerspace can be found for it at the library.
 *
 * <p>A user skill is backed by a {@link SkillCredential}. Without a valid
 * credential it is not imported into any hub and cannot be matched on.
 */
public class UserSkill {

    public enum Proficiency {
        /** Used the resource under guidance. */
        INTRODUCED,
        /** Used it independently, more than once. */
        PRACTISED,
        /** Can supervise others on it. Set only by an admin, never self-claimed. */
        CAN_TEACH
    }

    private String userSkillId;

    /** Owner's key fingerprint. */
    private String holderKeyFingerprint;

    /** Shared taxonomy term, copied from the hub skill it was earned against. */
    private String taxonomyTerm;

    private Proficiency proficiency;

    private SkillCredential credential;

    private Instant earnedAt;

    /**
     * Last time any hub re-verified it (another interaction, another admin).
     * Skills decay: something last confirmed years ago ranks lower.
     */
    private Instant lastConfirmedAt;

    /**
     * Whether the holder is willing to be matched on it. Per person, not per
     * hub; {@link SkillProfile} holds per-hub overrides.
     */
    private boolean offered;

    public UserSkill() {
        // TODO: pseudo-code
    }

    public UserSkill(SkillCredential credential) {
        // TODO: pseudo-code
    }

    public boolean isStale(Instant now) {
        // TODO: pseudo-code
        return false;
    }

    /** Merges a newer credential for the same term, keeping the higher proficiency. */
    public void reconfirm(SkillCredential newer) {
        // TODO: pseudo-code
    }

    // --- accessors --------------------------------------------------------

    public String getUserSkillId() {
        return userSkillId;
    }

    public String getHolderKeyFingerprint() {
        return holderKeyFingerprint;
    }

    public String getTaxonomyTerm() {
        return taxonomyTerm;
    }

    public Proficiency getProficiency() {
        return proficiency;
    }

    public SkillCredential getCredential() {
        return credential;
    }

    public Instant getEarnedAt() {
        return earnedAt;
    }

    public Instant getLastConfirmedAt() {
        return lastConfirmedAt;
    }

    public boolean isOffered() {
        return offered;
    }
}
