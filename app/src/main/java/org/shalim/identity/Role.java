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

    /** Base grants for the role, before restrictions are subtracted. */
    public Set<Permission> permissions() {
        // TODO: pseudo-code
        return null;
    }

    public boolean atLeast(Role other) {
        // TODO: pseudo-code
        return false;
    }

    /** Returns the lesser of this role and the cap. Used to enforce restrictions. */
    public Role cappedAt(Role cap) {
        // TODO: pseudo-code
        return null;
    }
}
