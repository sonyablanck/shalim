package org.shalim.identity;

import java.time.Instant;
import java.util.List;
import java.util.Set;

/**
 * One person's standing in one hub. This is where role, restrictions and
 * visibility live, so the same {@link User} can be an admin here and a guest
 * there without any object surgery.
 */
public class Membership {

    private String membershipId;
    private String userId;
    private String hubId;
    private Role role;
    private Instant joinedAt;
    private Instant lastSeenAt;

    /** Who admitted or promoted this member, for audit after a contested merge. */
    private String admittedByUserId;

    /**
     * Restrictions currently in force. Kept as a list rather than a single flag
     * so an expiring restriction and a permanent one can coexist and be
     * reasoned about separately.
     */
    private List<Restriction> restrictions;

    /** How willing this member is to be surfaced in Matchmaker results. */
    private Visibility visibility;

    /**
     * Guests are only permitted while physically present on the hub's verified
     * network; this records the link that vouched for them.
     */
    private String presenceProofId;

    /**
     * The hub's network claim as it was when this person joined, pinned on
     * their device. If a second hub later answers for the same network, this
     * device keeps following the pinned one. Only a migration signed by the
     * pinned hub's own key replaces it.
     */
    private String pinnedNetworkClaimId;

    public enum Visibility {
        /** Discoverable by any non-guest member of this hub. */
        HUB_WIDE,
        /** Only surfaced to admins, e.g. for sensitive skills. */
        ADMINS_ONLY,
        /** Never surfaced by Matchmaker. Skills still count toward the hub summary. */
        HIDDEN
    }

    public Membership() {
        // TODO: pseudo-code
    }

    public Membership(String userId, String hubId, Role role) {
        // TODO: pseudo-code
    }

    // --- permissions ------------------------------------------------------

    /** Permissions granted by the role, before restrictions are subtracted. */
    public Set<Permission> grantedPermissions() {
        // PSEUDO-CODE
        // RETURN role.permissions()
        return null;
    }

    /** Permissions actually available: role grants minus every active restriction. */
    public Set<Permission> effectivePermissions() {
        // PSEUDO-CODE
        //
        // Restrictions cap the ROLE, then permissions derive from the capped
        // role. Subtracting individual permissions instead would let a
        // restricted admin keep stray admin powers that no cap anticipated.
        //
        // effectiveRole = role
        // FOR EACH r IN activeRestrictions()
        //     effectiveRole = effectiveRole.cappedAt(r.roleCap)
        // RETURN effectiveRole.permissions()
        return null;
    }

    /**
     * As {@link #effectivePermissions()}, with the hub's authentication
     * standing applied as one more cap. Callers that hold the hub should use
     * this one.
     */
    public Set<Permission> effectivePermissions(org.shalim.hub.HubStanding standing) {
        // PSEUDO-CODE
        //
        // effectiveRole = role capped by every active restriction, as above
        // hubCap = standing == null ? GUEST-unless-admin : standing.roleCapFor(this)
        // IF hubCap != null -> effectiveRole = effectiveRole.cappedAt(hubCap)
        // RETURN effectiveRole.permissions()
        //
        // The same mechanism as a restriction, deliberately: a hub-level cap
        // lowers the role, permissions derive from the capped role, and no
        // stray member permission survives. Unlike a restriction it is not
        // about this person, so explainDenial() gives HubStanding.explain()
        // rather than anything that sounds like a sanction.
        return null;
    }

    public boolean can(Permission permission) {
        // PSEUDO-CODE
        // RETURN effectivePermissions().contains(permission)
        return false;
    }

    /**
     * Why a permission was denied, in language safe to show the user. People
     * told "no" with no reason assume the app is broken and move to a less safe
     * channel, so denials are always explained.
     */
    public String explainDenial(Permission permission) {
        // PSEUDO-CODE
        // IF can(permission) RETURN null
        // blocking = first r IN activeRestrictions()
        //            WHERE NOT r.roleCap.permissions().contains(permission)
        // IF blocking exists
        //     RETURN blocking.explanation
        //            + (blocking.appealable ? " You can ask a moderator to review this."
        //                                   : "")
        //            + (blocking.discharge == LEAVE_ORIGIN_HUB
        //               ? " This lifts if you leave the hub that caused it." : "")
        // RETURN "Your role in this hub does not include this."
        return null;
    }

    // --- role changes -----------------------------------------------------

    /** Changes role in place. No object replacement, so references stay valid. */
    public boolean setRole(Role newRole, String changedByUserId) {
        // TODO: pseudo-code
        return false;
    }

    public Role getRole() {
        // TODO: pseudo-code
        return role;
    }

    public boolean isAdmin() {
        // TODO: pseudo-code
        return false;
    }

    public boolean isGuest() {
        // TODO: pseudo-code
        return false;
    }

    // --- restrictions -----------------------------------------------------

    public void applyRestriction(Restriction restriction) {
        // TODO: pseudo-code
    }

    public boolean liftRestriction(String restrictionId, String liftedByUserId, String justification) {
        // TODO: pseudo-code
        return false;
    }

    public List<Restriction> activeRestrictions() {
        // PSEUDO-CODE
        // Caller-independent: expiry and discharge are evaluated here so a
        // stale restriction can never silently keep capping someone.
        //
        // currentHubIds = hub ids from the owning user's memberships
        // RETURN restrictions WHERE r.isActive(now)
        //                       AND NOT r.isDischarged(currentHubIds, now)
        return null;
    }

    public boolean isRestricted() {
        // TODO: pseudo-code
        return false;
    }

    // --- presence ---------------------------------------------------------

    public void markSeen(Instant when) {
        // TODO: pseudo-code
    }

    /** Guests lose access when their presence proof expires; members do not. */
    public boolean hasValidPresence(Instant now) {
        // TODO: pseudo-code
        return false;
    }

    public void setVisibility(Visibility visibility) {
        // TODO: pseudo-code
    }

    // --- accessors --------------------------------------------------------

    public String getMembershipId() {
        return membershipId;
    }

    public String getUserId() {
        return userId;
    }

    public String getHubId() {
        return hubId;
    }

    public Visibility getVisibility() {
        return visibility;
    }

    public Instant getJoinedAt() {
        return joinedAt;
    }

    public Instant getLastSeenAt() {
        return lastSeenAt;
    }
}
