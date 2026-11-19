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

    /** When the guest's presence proof lapses. Null for members, who need none. */
    private Instant presenceExpiresAt;

    private String roleChangedByUserId;
    private Instant roleChangedAt;

    /**
     * Which hubs the owning person currently belongs to, for discharging
     * LEAVE_ORIGIN_HUB restrictions. Set by {@link User} on the person's own
     * device. A hub's copy of a membership knows only its own hub, which is
     * the point: no hub learns where else a member belongs.
     */
    private transient java.util.function.Supplier<java.util.Set<String>> currentHubIds;

    public Membership() {
        this.membershipId = org.shalim.crypto.Bytes.randomId();
        this.restrictions = new java.util.ArrayList<>();
        this.visibility = Visibility.HUB_WIDE;
        this.joinedAt = Instant.now();
        this.lastSeenAt = joinedAt;
        this.currentHubIds = () -> hubId == null ? java.util.Set.of() : java.util.Set.of(hubId);
    }

    public Membership(String userId, String hubId, Role role) {
        this();
        this.userId = userId;
        this.hubId = hubId;
        this.role = role == null ? Role.GUEST : role;
    }

    /**
     * Stamps admission time from the hub's clock, not the JVM's. Joining
     * dates decide who may act as a prober (membership age), so they must
     * follow the hub's trusted time. Admission only.
     */
    public Membership joinedAt(Instant when) {
        if (when != null) {
            this.joinedAt = when;
            this.lastSeenAt = when;
        }
        return this;
    }

    /** Called by {@link User} so restriction discharge sees the person's whole hub set. */
    void bindHubSet(java.util.function.Supplier<java.util.Set<String>> hubs) {
        this.currentHubIds = hubs;
    }

    // --- permissions ------------------------------------------------------

    /** Permissions granted by the role, before restrictions are subtracted. */
    public Set<Permission> grantedPermissions() {
        return role == null ? java.util.Set.of() : role.permissions();
    }

    /** Role after every active restriction's cap. */
    public Role restrictedRole(Instant now) {
        //
        // Restrictions cap the ROLE, then permissions derive from the capped
        // role. Subtracting individual permissions instead would let a
        // restricted admin keep stray admin powers that no cap anticipated.
        Role effective = role == null ? Role.GUEST : role;
        for (Restriction r : activeRestrictions(now)) {
            effective = effective.cappedAt(r.getRoleCap());
        }
        return effective;
    }

    /** Permissions actually available: role grants minus every active restriction. */
    public Set<Permission> effectivePermissions() {
        return restrictedRole(Instant.now()).permissions();
    }

    /**
     * As {@link #effectivePermissions()}, with the hub's authentication
     * standing applied as one more cap. Callers that hold the hub should use
     * this one.
     */
    public Set<Permission> effectivePermissions(org.shalim.hub.HubStanding standing) {
        return effectiveRole(standing, Instant.now()).permissions();
    }

    /**
     * The role in force: restrictions first, then the hub-level cap. The same
     * mechanism as a restriction, deliberately: a hub-level cap lowers the role,
     * permissions derive from the capped role, and no stray member permission
     * survives. A missing standing is treated as UNAUTHENTICATED.
     */
    public Role effectiveRole(org.shalim.hub.HubStanding standing, Instant now) {
        Role effective = restrictedRole(now);
        Role hubCap = standing == null
                ? (role == Role.ADMIN ? null : Role.GUEST)
                : standing.roleCapFor(this);
        return effective.cappedAt(hubCap);
    }

    public boolean can(Permission permission) {
        return effectivePermissions().contains(permission);
    }

    public boolean can(Permission permission, org.shalim.hub.HubStanding standing) {
        return effectivePermissions(standing).contains(permission);
    }

    /**
     * Why a permission was denied, in language safe to show the user. People
     * told "no" with no reason assume the app is broken and move to a less safe
     * channel, so denials are always explained.
     */
    public String explainDenial(Permission permission) {
        if (can(permission)) {
            return null;
        }
        for (Restriction blocking : activeRestrictions()) {
            if (blocking.getRoleCap() != null && !blocking.getRoleCap().permissions().contains(permission)) {
                return blocking.getExplanation()
                        + (blocking.isAppealable() ? " You can ask a moderator to review this." : "")
                        + (blocking.getDischarge() == Restriction.Discharge.LEAVE_ORIGIN_HUB
                                ? " This lifts if you leave the hub that caused it." : "");
            }
        }
        return "Your role in this hub does not include this.";
    }

    /**
     * As above, with the hub's standing: a member capped by an unauthenticated
     * hub is given the hub's explanation, which is not about them.
     */
    public String explainDenial(Permission permission, org.shalim.hub.HubStanding standing) {
        if (can(permission, standing)) {
            return null;
        }
        if (can(permission)) {
            return standing == null ? org.shalim.hub.HubStanding.unauthenticatedExplanation() : standing.explain();
        }
        return explainDenial(permission);
    }

    // --- role changes -----------------------------------------------------

    /** Changes role in place. No object replacement, so references stay valid. */
    public boolean setRole(Role newRole, String changedByUserId) {
        if (newRole == null || newRole == role) {
            return false;
        }
        this.role = newRole;
        this.roleChangedByUserId = changedByUserId;
        this.roleChangedAt = Instant.now();
        if (newRole != Role.GUEST) {
            presenceExpiresAt = null; // members are not tied to presence
        }
        return true;
    }

    public Role getRole() {
        return role;
    }

    /** Holds the ADMIN role. Restrictions may still cap what it can do. */
    public boolean isAdmin() {
        return role == Role.ADMIN;
    }

    public boolean isGuest() {
        return role == Role.GUEST;
    }

    // --- restrictions -----------------------------------------------------

    public void applyRestriction(Restriction restriction) {
        if (restriction != null && restrictions.stream()
                .noneMatch(r -> r.getRestrictionId().equals(restriction.getRestrictionId()))) {
            restrictions.add(restriction);
        }
    }

    public boolean liftRestriction(String restrictionId, String liftedByUserId, String justification) {
        for (Restriction r : restrictions) {
            if (r.getRestrictionId().equals(restrictionId)) {
                return r.lift(liftedByUserId, justification);
            }
        }
        return false;
    }

    public List<Restriction> activeRestrictions() {
        return activeRestrictions(Instant.now());
    }

    /**
     * Caller-independent: expiry and discharge are evaluated here so a stale
     * restriction can never silently keep capping someone.
     */
    public List<Restriction> activeRestrictions(Instant now) {
        java.util.Set<String> hubs = currentHubIds.get();
        List<Restriction> out = new java.util.ArrayList<>();
        for (Restriction r : restrictions) {
            if (r.isActive(now) && !r.isDischarged(hubs, now)) {
                out.add(r);
            }
        }
        return out;
    }

    /** Every restriction ever applied here and not yet pruned, active or not. For moderators. */
    public List<Restriction> allRestrictions() {
        return List.copyOf(restrictions);
    }

    /** Drops lifted, expired and discharged restrictions older than {@code cutoff}. */
    public int pruneRestrictions(Instant cutoff, Instant now) {
        int before = restrictions.size();
        restrictions.removeIf(r -> {
            boolean ended = !r.isActive(now) || r.isDischarged(currentHubIds.get(), now);
            Instant endedAt = r.getLiftedAt() != null ? r.getLiftedAt()
                    : r.getExpiresAt() != null ? r.getExpiresAt() : r.getAppliedAt();
            return ended && endedAt != null && endedAt.isBefore(cutoff);
        });
        return before - restrictions.size();
    }

    public boolean isRestricted() {
        return !activeRestrictions().isEmpty();
    }

    // --- presence ---------------------------------------------------------

    public void markSeen(Instant when) {
        if (lastSeenAt == null || when.isAfter(lastSeenAt)) {
            this.lastSeenAt = when;
        }
    }

    /** Records the presence proof that admitted or renewed a guest. */
    public void recordPresence(org.shalim.hub.PresenceProof proof) {
        this.presenceProofId = proof.proofId();
        this.presenceExpiresAt = proof.getExpiresAt();
        markSeen(proof.getIssuedAt());
    }

    /** Guests lose access when their presence proof expires; members do not. */
    public boolean hasValidPresence(Instant now) {
        if (!isGuest()) {
            return true;
        }
        return presenceExpiresAt != null && now.isBefore(presenceExpiresAt);
    }

    public void setVisibility(Visibility visibility) {
        if (visibility != null) {
            this.visibility = visibility;
        }
    }

    public void setPinnedNetworkClaimId(String claimId) {
        this.pinnedNetworkClaimId = claimId;
    }

    public void setAdmittedByUserId(String userId) {
        this.admittedByUserId = userId;
    }

    /** Restores persisted state exactly. Persistence only. */
    public static Membership restore(String membershipId, String userId, String hubId, Role role,
                                     Instant joinedAt, Instant lastSeenAt, String admittedByUserId,
                                     Visibility visibility, String presenceProofId, Instant presenceExpiresAt,
                                     String pinnedNetworkClaimId, List<Restriction> restrictions) {
        Membership m = new Membership(userId, hubId, role);
        m.membershipId = membershipId;
        m.joinedAt = joinedAt;
        m.lastSeenAt = lastSeenAt;
        m.admittedByUserId = admittedByUserId;
        m.visibility = visibility;
        m.presenceProofId = presenceProofId;
        m.presenceExpiresAt = presenceExpiresAt;
        m.pinnedNetworkClaimId = pinnedNetworkClaimId;
        m.restrictions.addAll(restrictions);
        return m;
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

    public String getAdmittedByUserId() {
        return admittedByUserId;
    }

    public String getPresenceProofId() {
        return presenceProofId;
    }

    public Instant getPresenceExpiresAt() {
        return presenceExpiresAt;
    }

    public String getPinnedNetworkClaimId() {
        return pinnedNetworkClaimId;
    }

    public String getRoleChangedByUserId() {
        return roleChangedByUserId;
    }

    public Instant getRoleChangedAt() {
        return roleChangedAt;
    }
}
