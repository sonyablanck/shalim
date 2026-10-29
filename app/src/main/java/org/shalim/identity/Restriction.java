package org.shalim.identity;

import java.time.Instant;

/**
 * A cap placed on a {@link Membership}. Restrictions subtract from what a role
 * grants; they never add.
 *
 * <p>Scope is deliberately explicit. A restriction arising from one hub's
 * problems defaults to {@link Scope#THIS_HUB}: cross-hub propagation is
 * available but is an opt-in decision by the <em>receiving</em> hub, because
 * automatic global restriction turns "get someone to join a hub you have
 * poisoned" into a way to silence them everywhere.
 */
public class Restriction {

    private String restrictionId;
    private String membershipId;
    private Reason reason;
    private Scope scope;

    /** Role ceiling while this restriction is active, typically {@link Role#GUEST}. */
    private Role roleCap;

    private Instant appliedAt;

    /** Null means indefinite. Prefer an expiry wherever the reason permits one. */
    private Instant expiresAt;

    private String appliedByUserId;

    /** Shown to the restricted user. They are always told they are restricted, and why. */
    private String explanation;

    /** Whether the user has a route to contest this. Should almost always be true. */
    private boolean appealable;

    public enum Reason {
        /** Hub's TinyCensor artefact failed hash verification or was disabled. */
        COMPROMISED_CENSOR,
        /** Age assurance required by deployment policy and not satisfied. */
        AGE_NOT_ASSURED,
        /** Moderator action following an upheld censor flag. */
        MODERATION_ACTION,
        /** Guest whose presence proof has lapsed. */
        PRESENCE_LAPSED,
        /** User's own choice, e.g. stepping back from a hub temporarily. */
        SELF_IMPOSED
    }

    public enum Scope {
        /** Default. Affects only the hub where the cause arose. */
        THIS_HUB,
        /** Applies elsewhere only where a receiving hub has opted in. */
        FEDERATED,
        /**
         * Applies everywhere on this device regardless of hub policy. Reserved
         * for device-local causes such as age assurance, never for reputation.
         */
        DEVICE_WIDE
    }

    /**
     * What ends the restriction. Chiefly here so a federated cap can be
     * discharged by leaving the hub that caused it, rather than being a life
     * sentence.
     */
    public enum Discharge {
        /** Ends only when a moderator lifts it. */
        MANUAL,
        /** Ends at {@link #expiresAt}. */
        EXPIRY,
        /** Ends when the user leaves {@link #originHubId}. */
        LEAVE_ORIGIN_HUB,
        /** Ends when the origin hub's censor verifies again. */
        ORIGIN_HUB_REMEDIATED
    }

    private Discharge discharge;

    /**
     * Hub whose state caused this restriction. Note the privacy cost: for a
     * receiving hub to check a {@link Discharge#LEAVE_ORIGIN_HUB} condition it
     * must learn the user belongs to this hub, which builds a cross-hub
     * membership graph. Prefer person-level attestations where possible.
     */
    private String originHubId;

    public Restriction() {
        // TODO: pseudo-code
    }

    public Restriction(String membershipId, Reason reason, Scope scope, Role roleCap) {
        // TODO: pseudo-code
    }

    public boolean isActive(Instant now) {
        // TODO: pseudo-code
        return false;
    }

    /**
     * Whether a hub should honour this restriction, given that hub's policy.
     * A {@link Scope#FEDERATED} restriction is ignored unless the receiving hub
     * has chosen to trust the originating hub.
     */
    public boolean appliesIn(String hubId, org.shalim.hub.HubPolicy receivingPolicy) {
        // TODO: pseudo-code
        return false;
    }

    public boolean lift(String liftedByUserId, String justification) {
        // TODO: pseudo-code
        return false;
    }

    /**
     * Whether the discharge condition is met, given the hubs the user is still
     * in. Caller supplies the membership set so this class never holds it.
     */
    public boolean isDischarged(java.util.Set<String> currentHubIds, Instant now) {
        // PSEUDO-CODE
        // SWITCH discharge
        //    MANUAL                 -> RETURN false          // only lift() clears it
        //    EXPIRY                 -> RETURN expiresAt != null AND now > expiresAt
        //    LEAVE_ORIGIN_HUB       -> RETURN NOT currentHubIds.contains(originHubId)
        //    ORIGIN_HUB_REMEDIATED  -> RETURN false           // cleared by the origin hub
        return false;
    }

    // --- accessors --------------------------------------------------------

    public String getRestrictionId() {
        return restrictionId;
    }

    public Reason getReason() {
        return reason;
    }

    public Scope getScope() {
        return scope;
    }

    public Role getRoleCap() {
        return roleCap;
    }

    public Discharge getDischarge() {
        return discharge;
    }

    public String getOriginHubId() {
        return originHubId;
    }

    public String getExplanation() {
        return explanation;
    }

    public boolean isAppealable() {
        return appealable;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }
}
