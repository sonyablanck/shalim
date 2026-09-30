package org.shalim.skills;

import java.time.Instant;

/**
 * A claim that someone used a hub resource, waiting for an admin to verify it
 * into an earned skill.
 *
 * <p>This is the only way anyone — member or guest — adds a skill to their
 * profile. Self-declared skills no longer exist.
 *
 * <p>Pending interactions are a record of who used what, when, at this hub.
 * They are kept only until verified or rejected, then dropped; the credential
 * that results lives on the user's device, not the hub's. A hub keeps a log
 * entry that a skill was verified, with no resource or user named in the
 * detail.
 */
public class ResourceInteraction {

    public enum Status {
        PENDING,
        VERIFIED,
        REJECTED,
        /** Not reviewed within the window. Dropped, not rejected. */
        EXPIRED
    }

    private String interactionId;
    private String hubId;
    private String userKeyFingerprint;
    private String resourceId;

    /** Short note from the user, screened at USER_SKILL. Optional. */
    private String note;

    private Instant occurredAt;
    private Status status;

    private String verifiedByUserId;
    private Instant decidedAt;

    /** Proficiency the verifier assigned. The user cannot set this. */
    private UserSkill.Proficiency awardedProficiency;

    public ResourceInteraction() {
        // TODO: pseudo-code
    }

    public ResourceInteraction(String hubId, String userKeyFingerprint, String resourceId,
                               Instant occurredAt) {
        // TODO: pseudo-code
    }

    public boolean isPending() {
        return status == Status.PENDING;
    }

    // --- accessors --------------------------------------------------------

    public String getInteractionId() {
        return interactionId;
    }

    public String getHubId() {
        return hubId;
    }

    public String getUserKeyFingerprint() {
        return userKeyFingerprint;
    }

    public String getResourceId() {
        return resourceId;
    }

    public Status getStatus() {
        return status;
    }

    public UserSkill.Proficiency getAwardedProficiency() {
        return awardedProficiency;
    }
}
