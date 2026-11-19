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

    /** A skill not reconfirmed for this long ranks lower, and is shown as possibly rusty. */
    public static final java.time.Duration STALE_AFTER = java.time.Duration.ofDays(730);

    public UserSkill() {
        this.userSkillId = org.shalim.crypto.Bytes.randomId();
        this.offered = true;
    }

    public UserSkill(SkillCredential credential) {
        this();
        this.credential = credential;
        this.holderKeyFingerprint = credential.getSubjectKeyFingerprint();
        this.taxonomyTerm = credential.getTaxonomyTerm();
        this.proficiency = credential.getProficiency();
        this.earnedAt = dayStart(credential.getIssuedOn());
        this.lastConfirmedAt = earnedAt;
    }

    private static Instant dayStart(java.time.LocalDate day) {
        return day == null ? null : day.atStartOfDay(java.time.ZoneOffset.UTC).toInstant();
    }

    public boolean isStale(Instant now) {
        return lastConfirmedAt == null || lastConfirmedAt.plus(STALE_AFTER).isBefore(now);
    }

    /** Merges a newer credential for the same term, keeping the higher proficiency. */
    public void reconfirm(SkillCredential newer) {
        if (newer == null || !java.util.Objects.equals(taxonomyTerm, newer.getTaxonomyTerm())) {
            return;
        }
        Instant at = dayStart(newer.getIssuedOn());
        if (newer.getProficiency() != null && (proficiency == null || newer.getProficiency().compareTo(proficiency) > 0)) {
            proficiency = newer.getProficiency();
            credential = newer; // present the credential that proves the higher level
        }
        if (at != null && (lastConfirmedAt == null || at.isAfter(lastConfirmedAt))) {
            lastConfirmedAt = at;
            if (credential == null || newer.getProficiency() == proficiency) {
                credential = newer;
            }
        }
    }

    public void setOffered(boolean offered) {
        this.offered = offered;
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
