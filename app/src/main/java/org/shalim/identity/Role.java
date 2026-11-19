package org.shalim.identity;

import java.util.Set;

/**
 * Role held within a single hub. Ordered from least to most privileged; the
 * ordinal is deliberately meaningful so restrictions can express "cap this
 * membership at GUEST" without enumerating permissions.
 */
public enum Role {

    /**
     * Present on the hub's network but not a member. Can use resources and
     * earn skills from them, cannot query Matchmaker or see other members.
     * Also the cap applied to un-assured users on age-gated deployments, and
     * to every non-admin member of a hub that is not yet authenticated (see
     * {@code HubStanding}).
     */
    GUEST,

    /** Full participant: can query Matchmaker and request meetings. */
    MEMBER,

    /** Trusted member who can vet joiners and review censor flags. */
    MODERATOR,

    /**
     * Can change hub configuration, roles, resources and the model pinning
     * policy; verifies earned skills; sets up authentication with other hubs.
     */
    ADMIN;

    private static final Set<Permission> GUEST_GRANTS = java.util.Collections.unmodifiableSet(
            java.util.EnumSet.of(Permission.EDIT_OWN_SKILLS, Permission.RECORD_RESOURCE_USE,
                    Permission.PRESENT_SKILL_CREDENTIALS, Permission.VIEW_HUB_PROFILE,
                    Permission.VIEW_HUB_RESOURCES));

    private static final Set<Permission> MEMBER_GRANTS = union(GUEST_GRANTS,
            java.util.EnumSet.of(Permission.RUN_HUB_QUERY, Permission.REQUEST_MEETING,
                    Permission.RESPOND_TO_MEETING));

    /**
     * VIEW_MEMBERS sits here, not with MEMBER, although the enum lists it
     * under members. An ordinary member who could list the roster would hold
     * the directory that MeetingRequest's "no cold contact" rule exists to
     * deny them. Members find people only through query results.
     */
    private static final Set<Permission> MODERATOR_GRANTS = union(MEMBER_GRANTS,
            java.util.EnumSet.of(Permission.VIEW_MEMBERS, Permission.VIEW_LOG, Permission.INVITE_MEMBER,
                    Permission.APPROVE_MEMBER, Permission.REMOVE_MEMBER, Permission.REVIEW_CENSOR_FLAG));

    private static final Set<Permission> ADMIN_GRANTS = java.util.Collections.unmodifiableSet(
            java.util.EnumSet.allOf(Permission.class));

    private static Set<Permission> union(Set<Permission> base, Set<Permission> more) {
        java.util.EnumSet<Permission> all = java.util.EnumSet.copyOf(base);
        all.addAll(more);
        return java.util.Collections.unmodifiableSet(all);
    }

    /** Base grants for the role, before restrictions are subtracted. Each role includes the one below. */
    public Set<Permission> permissions() {
        return switch (this) {
            case GUEST -> GUEST_GRANTS;
            case MEMBER -> MEMBER_GRANTS;
            case MODERATOR -> MODERATOR_GRANTS;
            case ADMIN -> ADMIN_GRANTS;
        };
    }

    public boolean atLeast(Role other) {
        return other == null || compareTo(other) >= 0;
    }

    /** Returns the lesser of this role and the cap. Used to enforce restrictions. A null cap is no cap. */
    public Role cappedAt(Role cap) {
        return cap == null || compareTo(cap) <= 0 ? this : cap;
    }
}
