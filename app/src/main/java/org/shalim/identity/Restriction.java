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

    private Instant liftedAt;
    private String liftedByUserId;
    private String liftJustification;

    /** Set by the origin hub's signed notice that its censor verifies again. */
    private boolean originRemediated;

    public Restriction() {
        this.restrictionId = org.shalim.crypto.Bytes.randomId();
        this.appealable = true;
        this.discharge = Discharge.MANUAL;
    }

    /**
     * A restriction applied now, with the default explanation for its reason.
     * Refine it with the {@code with...} methods before applying it.
     */
    public Restriction(String membershipId, Reason reason, Scope scope, Role roleCap) {
        this();
        if (scope == Scope.DEVICE_WIDE && reason != Reason.AGE_NOT_ASSURED) {
            // Device-wide is for device-local causes. A reputational cap that
            // applied everywhere regardless of hub policy would be exactly the
            // global silencing this class exists to prevent.
            throw new IllegalArgumentException("DEVICE_WIDE is reserved for age assurance");
        }
        this.membershipId = membershipId;
        this.reason = reason;
        this.scope = scope;
        this.roleCap = roleCap;
        this.appliedAt = Instant.now();
        this.explanation = defaultExplanation(reason);
    }

    public Restriction appliedAt(Instant when) {
        this.appliedAt = when;
        return this;
    }

    public Restriction appliedBy(String userId) {
        this.appliedByUserId = userId;
        return this;
    }

    /** Sets an expiry and makes expiry the discharge, unless another discharge was chosen. */
    public Restriction expiring(Instant when) {
        this.expiresAt = when;
        if (discharge == Discharge.MANUAL) {
            this.discharge = Discharge.EXPIRY;
        }
        return this;
    }

    public Restriction dischargedBy(Discharge discharge) {
        this.discharge = discharge;
        return this;
    }

    public Restriction originatingIn(String hubId) {
        this.originHubId = hubId;
        return this;
    }

    public Restriction explained(String explanation) {
        if (explanation == null || explanation.isBlank()) {
            throw new IllegalArgumentException("a restriction must always be explained");
        }
        this.explanation = explanation;
        return this;
    }

    /** Use sparingly: almost every restriction should be contestable. */
    public Restriction notAppealable() {
        this.appealable = false;
        return this;
    }

    static String defaultExplanation(Reason reason) {
        if (reason == null) {
            return "Your access here is limited for now.";
        }
        return switch (reason) {
            case COMPROMISED_CENSOR -> "A hub you belong to cannot currently vouch for you, so you have guest access here.";
            case AGE_NOT_ASSURED -> "This hub requires age assurance for full membership.";
            case MODERATION_ACTION -> "A moderator has limited your access here.";
            case PRESENCE_LAPSED -> "Guest access lasts while you are at the hub. Reconnect to its Wi-Fi to continue.";
            case SELF_IMPOSED -> "You chose to step back from this hub.";
        };
    }

    /** In force: applied, not lifted, not past its expiry. */
    public boolean isActive(Instant now) {
        if (liftedAt != null) {
            return false;
        }
        if (appliedAt != null && now.isBefore(appliedAt)) {
            return false;
        }
        return expiresAt == null || now.isBefore(expiresAt);
    }

    /**
     * Whether a hub should honour this restriction, given that hub's policy.
     * A {@link Scope#FEDERATED} restriction is ignored unless the receiving hub
     * has chosen to trust the originating hub.
     */
    public boolean appliesIn(String hubId, org.shalim.hub.HubPolicy receivingPolicy) {
        if (scope == null) {
            return false;
        }
        return switch (scope) {
            // Raised here, or carrying no origin because this hub raised it itself.
            case THIS_HUB -> originHubId == null || originHubId.equals(hubId);
            // No origin: this hub applied it on evidence it verified itself (an
            // attestation it checked). With an origin: only by the receiving
            // hub's own opt-in.
            case FEDERATED -> originHubId == null || originHubId.equals(hubId)
                    || (receivingPolicy != null && receivingPolicy.honoursRestrictionsFrom(originHubId));
            case DEVICE_WIDE -> reason == Reason.AGE_NOT_ASSURED;
        };
    }

    /** Lifts the restriction. A justification is required, so lifting is as accountable as applying. */
    public boolean lift(String liftedByUserId, String justification) {
        if (liftedAt != null || justification == null || justification.isBlank()) {
            return false;
        }
        this.liftedAt = Instant.now();
        this.liftedByUserId = liftedByUserId;
        this.liftJustification = justification;
        return true;
    }

    /** The origin hub announced, signed, that its censor verifies again. */
    public void markOriginRemediated() {
        this.originRemediated = true;
    }

    /**
     * Whether the discharge condition is met, given the hubs the user is still
     * in. Caller supplies the membership set so this class never holds it.
     */
    public boolean isDischarged(java.util.Set<String> currentHubIds, Instant now) {
        if (discharge == null) {
            return false;
        }
        return switch (discharge) {
            case MANUAL -> false; // only lift() clears it
            case EXPIRY -> expiresAt != null && !now.isBefore(expiresAt);
            case LEAVE_ORIGIN_HUB -> originHubId != null && currentHubIds != null
                    && !currentHubIds.contains(originHubId);
            case ORIGIN_HUB_REMEDIATED -> originRemediated;
        };
    }

    public String getMembershipId() {
        return membershipId;
    }

    public Instant getAppliedAt() {
        return appliedAt;
    }

    public String getAppliedByUserId() {
        return appliedByUserId;
    }

    public Instant getLiftedAt() {
        return liftedAt;
    }

    public String getLiftedByUserId() {
        return liftedByUserId;
    }

    public String getLiftJustification() {
        return liftJustification;
    }

    public boolean isOriginRemediated() {
        return originRemediated;
    }

    /** Restores persisted lift state. Persistence only. */
    public void restoreLift(Instant liftedAt, String liftedByUserId, String justification) {
        this.liftedAt = liftedAt;
        this.liftedByUserId = liftedByUserId;
        this.liftJustification = justification;
    }

    /** Restores a persisted restriction exactly. Persistence only. */
    public static Restriction restore(String restrictionId, String membershipId, Reason reason, Scope scope,
                                      Role roleCap, Instant appliedAt, Instant expiresAt, String appliedByUserId,
                                      String explanation, boolean appealable, Discharge discharge,
                                      String originHubId, boolean originRemediated) {
        Restriction r = new Restriction();
        r.restrictionId = restrictionId;
        r.membershipId = membershipId;
        r.reason = reason;
        r.scope = scope;
        r.roleCap = roleCap;
        r.appliedAt = appliedAt;
        r.expiresAt = expiresAt;
        r.appliedByUserId = appliedByUserId;
        r.explanation = explanation;
        r.appealable = appealable;
        r.discharge = discharge;
        r.originHubId = originHubId;
        r.originRemediated = originRemediated;
        return r;
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
