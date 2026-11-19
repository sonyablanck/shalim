package org.shalim.hub;

import java.time.Instant;
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

    /** The fortnight. Fixed: may be shortened, never lengthened. */
    public static final int MEETING_REQUEST_RETENTION_DAYS = 14;

    public HubPolicy() {
        this.posture = Posture.COMMUNITY;
        this.minimumAssuranceMethod = AgeAssurance.Method.SELF_DECLARED;
        this.trustedRestrictionSources = new java.util.ArrayList<>();
        this.censorFailureMode = CensorFailureMode.DISABLE_QUERIES;
        this.unlockBasis = UnlockBasis.INBOUND_REQUIRED;
        this.meetingRequestRetentionDays = MEETING_REQUEST_RETENTION_DAYS;
        this.withholdOutcomesUnderAppeal = true;
        this.encryptSkillsAtRest = true;
        // Decided 19 November 2026: meeting requests are replayed at every hub.
        // Receipts prove a request was logged, not that it was judged honestly.
        this.replayMeetingRequests = true;
    }

    /**
     * Sensible defaults for a posture. Callers may then tighten, not loosen:
     * {@link #validate()} reports any setting looser than its posture's
     * default as an issue to be shown to admins and disclosed to members.
     */
    public static HubPolicy defaultsFor(Posture posture) {
        HubPolicy p = new HubPolicy();
        p.posture = posture == null ? Posture.COMMUNITY : posture;
        switch (p.posture) {
            case INSTITUTIONAL -> {
                // UK-style duty: self-declaration is not enough, so the floor is
                // on-device estimation, which keeps no image.
                p.requireAgeAssurance = true;
                p.minimumAssuranceMethod = AgeAssurance.Method.ON_DEVICE_ESTIMATION;
                p.censorFailureMode = CensorFailureMode.QUEUE_FOR_REVIEW;
                p.attestationTtlHours = 168;
                p.logRetentionDays = 90;
                p.allowPanicWipe = false;
                p.allowGuests = true;
                p.guestPresenceTtlMinutes = 60;
            }
            case COMMUNITY -> {
                p.requireAgeAssurance = false;
                p.censorFailureMode = CensorFailureMode.QUEUE_FOR_REVIEW;
                p.attestationTtlHours = 72;
                p.logRetentionDays = 30;
                p.allowPanicWipe = true;
                p.allowGuests = true;
                p.guestPresenceTtlMinutes = 30;
            }
            case HIGH_RISK -> {
                // Minimal retention, nothing that identifies anyone, and no walk-ins:
                // under surveillance a stranger on the Wi-Fi is as likely to be
                // looking for the hub as looking for help.
                p.requireAgeAssurance = false;
                p.censorFailureMode = CensorFailureMode.DISABLE_QUERIES;
                p.attestationTtlHours = 48;
                p.logRetentionDays = 7;
                p.allowPanicWipe = true;
                p.allowGuests = false;
                p.guestPresenceTtlMinutes = 15;
            }
        }
        return p;
    }

    /** Whether this hub honours a restriction raised by another hub. */
    public boolean honoursRestrictionsFrom(String originHubId) {
        return originHubId != null && trustedRestrictionSources.contains(originHubId);
    }

    /** Whether a user's assurance state permits more than guest access here. */
    public boolean permitsFullMembership(AgeAssurance assurance) {
        return permitsFullMembership(assurance, Instant.now());
    }

    public boolean permitsFullMembership(AgeAssurance assurance, Instant now) {
        if (!requireAgeAssurance) {
            return true;
        }
        return assurance != null && assurance.isValid(now) && assurance.satisfies(minimumAssuranceMethod);
    }

    /** Flags internally inconsistent or loosened policy. Empty means consistent. */
    public List<String> validate() {
        List<String> issues = new java.util.ArrayList<>();
        HubPolicy floor = defaultsFor(posture);
        if (censorFailureMode == null) {
            issues.add("No censor failure mode is set.");
        }
        if (requireAgeAssurance && (minimumAssuranceMethod == null
                || minimumAssuranceMethod == AgeAssurance.Method.NONE)) {
            issues.add("Age assurance is required but no acceptable method is set.");
        }
        if (allowGuests && guestPresenceTtlMinutes <= 0) {
            issues.add("Guests are allowed but their presence proofs would expire immediately.");
        }
        if (attestationTtlHours <= 0) {
            issues.add("Attestations would expire immediately.");
        }
        if (meetingRequestRetentionDays > MEETING_REQUEST_RETENTION_DAYS) {
            issues.add("Meeting requests are kept longer than a fortnight.");
        }
        if (unlockBasis == UnlockBasis.ANY_DIRECTION) {
            // Decided 18 November 2026: only an inbound link is evidence about
            // this hub's own censor.
            issues.add("This hub can unlock by auditing others, which says nothing about its own censor.");
        }
        if (!replayMeetingRequests) {
            // No posture is exempt: posture is self-declared, so an exemption
            // would be claimed by exactly the hubs replay exists to catch.
            issues.add("Meeting requests are kept out of replay, so a tampered censor could pass them unseen.");
        }
        if (federateModerationOutcomes && !withholdOutcomesUnderAppeal) {
            issues.add("Moderation outcomes would be shared while still under appeal.");
        }
        if (posture == Posture.HIGH_RISK) {
            if (requireAgeAssurance && minimumAssuranceMethod == AgeAssurance.Method.EXTERNAL_ATTESTATION) {
                issues.add("HIGH_RISK with external age attestation leaves an identity trail outside the hub.");
            }
            if (publishRestrictions || federateModerationOutcomes) {
                issues.add("HIGH_RISK hubs should not share restrictions or moderation outcomes.");
            }
            if (!encryptSkillsAtRest) {
                issues.add("HIGH_RISK hubs must encrypt the skills layer at rest.");
            }
        }
        if (posture == Posture.INSTITUTIONAL && !requireAgeAssurance) {
            issues.add("INSTITUTIONAL hubs are expected to require age assurance.");
        }
        // Looser than the posture's floor.
        if (logRetentionDays > floor.logRetentionDays) {
            issues.add("Log retention is longer than the " + posture + " default of "
                    + floor.logRetentionDays + " days.");
        }
        if (attestationTtlHours > floor.attestationTtlHours) {
            issues.add("Attestations last longer than the " + posture + " default.");
        }
        if (floor.requireAgeAssurance && requireAgeAssurance && minimumAssuranceMethod != null
                && minimumAssuranceMethod.compareTo(floor.minimumAssuranceMethod) < 0) {
            issues.add("The accepted age-assurance method is weaker than the " + posture + " default.");
        }
        if (!floor.allowGuests && allowGuests) {
            issues.add("Walk-in guests are allowed, which the " + posture + " posture does not.");
        }
        if (floor.allowPanicWipe && !allowPanicWipe) {
            issues.add("Panic wipe is off, which the " + posture + " posture expects on.");
        }
        return issues;
    }

    /** Plain-language summary shown before joining, so consent is informed. */
    public String disclosureSummary() {
        StringBuilder b = new StringBuilder();
        b.append(switch (posture) {
            case INSTITUTIONAL -> "This hub is run by an accountable institution.";
            case COMMUNITY -> "This is a community-run hub.";
            case HIGH_RISK -> "This hub keeps as little as possible, because it operates under risk.";
        }).append('\n');
        b.append(requireAgeAssurance
                ? "Full membership needs age assurance (" + describe(minimumAssuranceMethod)
                  + " or stronger). Nothing that identifies you is kept, only that you were assured."
                : "No age check is asked for.").append('\n');
        b.append("Activity records are kept for ").append(logRetentionDays)
                .append(" days; meeting requests for ").append(meetingRequestRetentionDays).append(" days.\n");
        b.append(encryptSkillsAtRest ? "Skills held here are encrypted on the hub's devices."
                : "Skills held here are not encrypted on the hub's devices.").append('\n');
        if (allowPanicWipe) {
            b.append("Admins can wipe this hub's data from a device in an emergency.\n");
        }
        b.append(allowGuests ? "Walk-in guests may use resources while they are here."
                : "There are no walk-in guests.").append('\n');
        b.append(trustedRestrictionSources.isEmpty() ? "Restrictions from other hubs are not honoured."
                : "Restrictions from " + trustedRestrictionSources.size() + " other hub(s) are honoured.").append('\n');
        b.append(federateModerationOutcomes ? "Moderation decisions here may be shared with other hubs."
                : "Moderation decisions here stay here.").append('\n');
        b.append(replayMeetingRequests
                ? "To check this hub's safety screening, another hub's device may briefly read a small random sample"
                  + " of questions and meeting requests, with no names attached, and then discard them."
                : "Meeting requests are not checked by other hubs.").append('\n');
        b.append(requireGoodStanding ? "Full membership needs a current proof of good standing."
                : "No proof of good standing is asked for.");
        return b.toString();
    }

    private static String describe(AgeAssurance.Method m) {
        if (m == null) {
            return "any method";
        }
        return switch (m) {
            case NONE -> "no check";
            case SELF_DECLARED -> "your own declaration";
            case VOUCHED_BY_MEMBER -> "an adult member vouching";
            case ON_DEVICE_ESTIMATION -> "estimation on your own device, keeping no image";
            case EXTERNAL_ATTESTATION -> "a yes/no from an outside provider";
        };
    }

    // --- changes ----------------------------------------------------------
    // Applied through HubAdministration.changePolicy, which checks
    // EDIT_HUB_POLICY, logs POLICY_CHANGED and re-runs validate().

    /** A blank policy at a posture, for restoring persisted settings through the setters. */
    public static HubPolicy restoring(Posture posture) {
        HubPolicy p = new HubPolicy();
        p.posture = posture;
        p.trustedRestrictionSources = new java.util.ArrayList<>();
        return p;
    }

    public HubPolicy copy() {
        HubPolicy p = new HubPolicy();
        p.hubId = hubId;
        p.posture = posture;
        p.requireAgeAssurance = requireAgeAssurance;
        p.minimumAssuranceMethod = minimumAssuranceMethod;
        p.trustedRestrictionSources = new java.util.ArrayList<>(trustedRestrictionSources);
        p.publishRestrictions = publishRestrictions;
        p.requireGoodStanding = requireGoodStanding;
        p.federateModerationOutcomes = federateModerationOutcomes;
        p.withholdOutcomesUnderAppeal = withholdOutcomesUnderAppeal;
        p.attestationTtlHours = attestationTtlHours;
        p.requiredCensorPinHash = requiredCensorPinHash;
        p.censorFailureMode = censorFailureMode;
        p.unlockBasis = unlockBasis;
        p.auditSchedule = auditSchedule;
        p.replayMeetingRequests = replayMeetingRequests;
        p.logRetentionDays = logRetentionDays;
        p.meetingRequestRetentionDays = meetingRequestRetentionDays;
        p.encryptSkillsAtRest = encryptSkillsAtRest;
        p.allowPanicWipe = allowPanicWipe;
        p.allowGuests = allowGuests;
        p.guestPresenceTtlMinutes = guestPresenceTtlMinutes;
        return p;
    }

    public void setHubId(String hubId) {
        this.hubId = hubId;
    }

    public void setAgeAssurance(boolean require, AgeAssurance.Method minimum) {
        this.requireAgeAssurance = require;
        this.minimumAssuranceMethod = minimum;
    }

    public void trustRestrictionsFrom(String hubId) {
        if (hubId != null && !trustedRestrictionSources.contains(hubId)) {
            trustedRestrictionSources.add(hubId);
        }
    }

    public void distrustRestrictionsFrom(String hubId) {
        trustedRestrictionSources.remove(hubId);
    }

    public void setPublishRestrictions(boolean publish) {
        this.publishRestrictions = publish;
    }

    public void setRequireGoodStanding(boolean require) {
        this.requireGoodStanding = require;
    }

    public void setFederateModerationOutcomes(boolean federate) {
        this.federateModerationOutcomes = federate;
    }

    public void setWithholdOutcomesUnderAppeal(boolean withhold) {
        this.withholdOutcomesUnderAppeal = withhold;
    }

    public void setAttestationTtlHours(int hours) {
        this.attestationTtlHours = hours;
    }

    public void setRequiredCensorPinHash(String hash) {
        this.requiredCensorPinHash = hash;
    }

    public void setCensorFailureMode(CensorFailureMode mode) {
        this.censorFailureMode = mode;
    }

    public void setUnlockBasis(UnlockBasis basis) {
        this.unlockBasis = basis;
    }

    public void setAuditSchedule(org.shalim.trust.AuditSchedule schedule) {
        this.auditSchedule = schedule;
    }

    public void setReplayMeetingRequests(boolean replay) {
        this.replayMeetingRequests = replay;
    }

    public void setLogRetentionDays(int days) {
        if (days < 1) {
            throw new IllegalArgumentException("at least one day of log is needed to sync");
        }
        this.logRetentionDays = days;
    }

    /** May be shortened, never lengthened past a fortnight. */
    public void setMeetingRequestRetentionDays(int days) {
        if (days < 1 || days > MEETING_REQUEST_RETENTION_DAYS) {
            throw new IllegalArgumentException("meeting requests are kept between 1 and 14 days");
        }
        this.meetingRequestRetentionDays = days;
    }

    public void setEncryptSkillsAtRest(boolean encrypt) {
        this.encryptSkillsAtRest = encrypt;
    }

    public void setAllowPanicWipe(boolean allow) {
        this.allowPanicWipe = allow;
    }

    public void setAllowGuests(boolean allow) {
        this.allowGuests = allow;
    }

    public void setGuestPresenceTtlMinutes(int minutes) {
        this.guestPresenceTtlMinutes = minutes;
    }

    public String getHubId() {
        return hubId;
    }

    public AgeAssurance.Method getMinimumAssuranceMethod() {
        return minimumAssuranceMethod;
    }

    public List<String> getTrustedRestrictionSources() {
        return List.copyOf(trustedRestrictionSources);
    }

    public boolean isPublishRestrictions() {
        return publishRestrictions;
    }

    public boolean isEncryptSkillsAtRest() {
        return encryptSkillsAtRest;
    }

    public boolean isAllowPanicWipe() {
        return allowPanicWipe;
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

    public int getGuestPresenceTtlMinutes() {
        return guestPresenceTtlMinutes;
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
