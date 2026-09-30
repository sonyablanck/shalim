package org.shalim.hub;

import java.util.List;
import org.shalim.identity.AgeAssurance;

/**
 * Per-hub configuration for the choices that cannot be made globally.
 *
 * <p>Chiefly: age assurance and threat posture pull in opposite directions.
 * Proving your age means identifying yourself, and in a repressive setting the
 * identification is the danger. A UK library hub can reasonably demand
 * assurance; a hub operating under an internet kill switch cannot be asked to.
 * So the choice is made per deployment, recorded here, and shown to people
 * <em>before</em> they join.
 */
public class HubPolicy {

    /**
     * Broad operating posture. Affects defaults across assurance, logging
     * retention, and how much metadata sync is willing to leak.
     */
    public enum Posture {
        /** Public-facing, legally accountable, e.g. a UK library. Assurance on. */
        INSTITUTIONAL,
        /** Ordinary community hub. Balanced defaults. */
        COMMUNITY,
        /** Operating under surveillance. Minimal retention, no external attestation. */
        HIGH_RISK
    }

    private String hubId;
    private Posture posture;

    // --- age assurance ----------------------------------------------------

    /** Whether adults-only assurance is required to hold more than GUEST. */
    private boolean requireAgeAssurance;

    /** Weakest acceptable method when assurance is required. */
    private AgeAssurance.Method minimumAssuranceMethod;

    // --- restriction federation -------------------------------------------

    /**
     * Hubs whose federated restrictions this hub honours. Empty by default:
     * accepting restrictions from strangers lets anyone who can compromise one
     * hub silence its members everywhere, which is a griefing vector and, in a
     * hostile state, a targeting tool.
     */
    private List<String> trustedRestrictionSources;

    /** Whether to publish our own restrictions for other hubs to consider. */
    private boolean publishRestrictions;

    /**
     * Whether members must present a valid good-standing proof to hold more
     * than GUEST. Off by default: requiring it is a real cost to anyone with
     * patchy connectivity, and the failure mode punishes the wrong people.
     */
    private boolean requireGoodStanding;

    /**
     * Whether moderation outcomes decided here may be shared with other hubs.
     * Off by default; most moderation is local business.
     */
    private boolean federateModerationOutcomes;

    /**
     * Whether to withhold an outcome attestation while the subject is
     * appealing, so a contested finding is not exported as settled fact.
     */
    private boolean withholdOutcomesUnderAppeal;

    /** How long issued attestations remain valid. */
    private int attestationTtlHours;

    // --- censor -----------------------------------------------------------

    /** Expected censor artefact. Peers diverging from this are treated as compromised. */
    private String requiredCensorPinHash;

    /** What to do when the censor cannot be verified. Never "carry on unscreened". */
    private CensorFailureMode censorFailureMode;

    public enum CensorFailureMode {
        /** Queries disabled until the censor is restored. Safest, least usable. */
        DISABLE_QUERIES,
        /** Queries run, results held for moderator review before display. */
        QUEUE_FOR_REVIEW,
        /** Fall back to a bundled blocklist. Weaker, but keeps the hub alive. */
        BLOCKLIST_ONLY
    }

    // --- authentication ---------------------------------------------------

    /** Which direction of authentication ends a hub's guest-only period. */
    public enum UnlockBasis {
        /**
         * Any counting link, inbound or outbound. The rule as requested: an
         * admin authenticating a hub they belong to unlocks this hub.
         */
        ANY_DIRECTION,
        /**
         * Only an inbound link — another hub having checked THIS hub's censor.
         * Recommended: an outbound link says the peer is behaving, which is no
         * evidence about this hub.
         */
        INBOUND_REQUIRED
    }

    private UnlockBasis unlockBasis;

    /**
     * Daily probing of peers this hub authenticates. Every probe and outcome
     * is kept in the ProbeLedger for {@link #meetingRequestRetentionDays} —
     * the same period as meeting requests — and then dropped.
     *
     * <p>Not a substitute for {@link #requiredCensorPinHash}: a pin is a claim
     * about what a hub is running, an audit is a measurement of what it does.
     * A hub that has been hooked passes the first and fails the second.
     */
    private org.shalim.trust.AuditSchedule auditSchedule;

    /**
     * Whether leaves on the MEETING_REQUEST surface may be opened for replay.
     * Off by default: a meeting request is a private message between two
     * members, and opening one to another hub is a larger intrusion than
     * opening a question to the hub. The cost is that meeting-request
     * screening is checked only through members' receipts, not by replay.
     * See the README's open questions.
     */
    private boolean replayMeetingRequests;

    // --- retention --------------------------------------------------------

    /** Days of log history kept. Short retention limits harm from device seizure. */
    private int logRetentionDays;

    /**
     * Days of meeting-request history kept. Fixed at a fortnight and not
     * lengthened by {@link #logRetentionDays}: a record of who approached whom
     * is more dangerous on a seized device than the rest of the log combined.
     */
    private int meetingRequestRetentionDays;

    /** Whether the skills layer is encrypted at rest with a member-held key. */
    private boolean encryptSkillsAtRest;

    /**
     * Whether a duress action wipes hub data on this device. Relevant where
     * possession of a membership list is itself dangerous.
     */
    private boolean allowPanicWipe;

    // --- guests -----------------------------------------------------------

    /** Whether walk-in guests may use hub resources at all. */
    private boolean allowGuests;

    /** Minutes a guest's presence proof stays valid after leaving the network. */
    private int guestPresenceTtlMinutes;

    public HubPolicy() {
        // TODO: pseudo-code
    }

    /** Sensible defaults for a posture. Callers may then tighten, not loosen. */
    public static HubPolicy defaultsFor(Posture posture) {
        // TODO: pseudo-code
        return null;
    }

    /** Whether this hub honours a restriction raised by another hub. */
    public boolean honoursRestrictionsFrom(String originHubId) {
        // TODO: pseudo-code
        return false;
    }

    /** Whether a user's assurance state permits more than guest access here. */
    public boolean permitsFullMembership(AgeAssurance assurance) {
        // TODO: pseudo-code
        return false;
    }

    /** Flags internally inconsistent policy, e.g. HIGH_RISK with external attestation. */
    public List<String> validate() {
        // TODO: pseudo-code
        return null;
    }

    /** Plain-language summary shown before joining, so consent is informed. */
    public String disclosureSummary() {
        // TODO: pseudo-code
        return null;
    }

    // --- accessors --------------------------------------------------------

    public Posture getPosture() {
        return posture;
    }

    public boolean isRequireAgeAssurance() {
        return requireAgeAssurance;
    }

    public CensorFailureMode getCensorFailureMode() {
        return censorFailureMode;
    }

    public String getRequiredCensorPinHash() {
        return requiredCensorPinHash;
    }

    public boolean isRequireGoodStanding() {
        return requireGoodStanding;
    }

    public boolean isFederateModerationOutcomes() {
        return federateModerationOutcomes;
    }

    public boolean isWithholdOutcomesUnderAppeal() {
        return withholdOutcomesUnderAppeal;
    }

    public int getAttestationTtlHours() {
        return attestationTtlHours;
    }

    public boolean isAllowGuests() {
        return allowGuests;
    }

    public int getLogRetentionDays() {
        return logRetentionDays;
    }

    public int getMeetingRequestRetentionDays() {
        return meetingRequestRetentionDays;
    }

    public boolean isReplayMeetingRequests() {
        return replayMeetingRequests;
    }

    public UnlockBasis getUnlockBasis() {
        return unlockBasis;
    }

    /** Null until an admin sets up a first authentication link. */
    public org.shalim.trust.AuditSchedule getAuditSchedule() {
        return auditSchedule;
    }
}
