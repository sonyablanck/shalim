package org.shalim.hub;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;
import org.shalim.attestation.AttestationVerifier;
import org.shalim.attestation.AttestationWallet;
import org.shalim.attestation.ModerationOutcome;
import org.shalim.identity.AgeAssurance;
import org.shalim.identity.Membership;
import org.shalim.identity.Permission;
import org.shalim.identity.Restriction;
import org.shalim.identity.Role;
import org.shalim.skills.HubResource;
import org.shalim.skills.ResourceInteraction;
import org.shalim.skills.SkillCredential;
import org.shalim.skills.UserSkill;

/**
 * Hub core: everything an admin or moderator does to a hub, with the
 * permission check, the invariant and the log entry in one place.
 *
 * <p>Every method that acts on behalf of a person takes that person's user
 * id and checks their effective permission <em>under the hub's standing</em>.
 * A moderator in an unauthenticated hub is capped at guest like everyone else
 * who is not an admin. Every change is logged under the hub key, with ids and
 * coarse detail only, never free text about a person.
 *
 * <p>Invariants kept here:
 * <ul>
 *   <li>a hub always has at least one admin while it has other members;</li>
 *   <li>nobody acts on someone of equal or higher role, except an admin;</li>
 *   <li>no one is admitted above MEMBER; roles above are assigned;</li>
 *   <li>a moderator never decides about themselves.</li>
 * </ul>
 */
public class HubAdministration {

    private final Hub hub;
    private final HubRuntime runtime;

    public HubAdministration(Hub hub, HubRuntime runtime) {
        this.hub = hub;
        this.runtime = runtime;
    }

    // --- creation ---------------------------------------------------------

    /** What creating a hub needs. The network must already carry a signed claim. */
    public record Creation(String name, String description, HubPolicy policy, HubLocation location,
                           HubNetwork network, String foundingAdminUserId, List<HubResource> resources) {
    }

    /** A new hub, or why not. */
    public record Created(Hub hub, List<String> problems) {
        public boolean ok() {
            return hub != null;
        }
    }

    /**
     * Creates a hub. Run after {@code NetworkClaimService.mayCreateHubHere}
     * has allowed it and the claim has been made with the new hub key.
     *
     * <p>Checks premises, claim and policy; screens every resource at
     * RESOURCE_DESCRIPTION; derives hub skills; starts UNAUTHENTICATED, so
     * every non-admin is a guest until an admin sets up authentication; runs
     * the local censor check; and logs it all.
     */
    public static Created create(Creation c, HubRuntime runtime) {
        List<String> problems = new ArrayList<>();
        Instant now = runtime.now();
        if (c.name() == null || c.name().isBlank()) {
            problems.add("A hub needs a name.");
        }
        if (c.location() == null || !c.location().isComplete()) {
            problems.add("A hub needs premises: a label, an address and a chosen precision.");
        }
        if (c.network() == null || c.network().getClaim() == null || runtime.getHubKey() == null
                || !c.network().getClaim().verify(runtime.getHubKey().publicKey())) {
            problems.add("A hub needs a network claim signed by its own key.");
        }
        if (c.foundingAdminUserId() == null) {
            problems.add("A hub needs a founding admin.");
        }
        if (c.policy() == null) {
            problems.add("A hub needs a policy.");
        } else {
            problems.addAll(c.policy().validate());
        }
        if (c.resources() == null || c.resources().isEmpty()) {
            problems.add("A hub needs at least one resource: it is what guests can use and what search shows.");
        }
        if (!problems.isEmpty()) {
            return new Created(null, problems);
        }
        String hubId = org.shalim.crypto.Bytes.randomId();
        HubPolicy policy = c.policy().copy();
        policy.setHubId(hubId);
        Hub hub = new Hub(hubId, c.name(), policy, c.location(), c.network(), c.foundingAdminUserId());
        hub.setDescription(c.description());
        hub.setCreatedAt(now);
        hub.setCensorLog(new CensorDecisionLog(runtime.getHubKey().fingerprint()));
        HubRuntime rt = runtime.forHub(hub);
        rt.log(HubLog.EventType.HUB_CREATED, c.foundingAdminUserId(), hubId, policy.getPosture().name(), now);
        rt.log(HubLog.EventType.NETWORK_CLAIMED, c.foundingAdminUserId(), c.network().getClaim().getClaimId(), null,
                now);
        HubAdministration admin = new HubAdministration(hub, rt);
        admin.checkCensorIntegrity(now);
        for (HubResource r : c.resources()) {
            if (hub.getSkillsLayer().addResource(r, rt.getCensor()).isPresent()) {
                rt.log(HubLog.EventType.RESOURCE_ADDED, c.foundingAdminUserId(), r.getResourceId(), null, now);
            }
        }
        if (!hub.getSkillsLayer().hasResources()) {
            return new Created(null, List.of("Every resource was refused by the censor."));
        }
        admin.rederiveHubSkills(c.foundingAdminUserId(), now);
        return new Created(hub, policy.validate());
    }

    // --- membership -------------------------------------------------------

    /**
     * Admits a member. The actor needs APPROVE_MEMBER. Nobody is admitted
     * above MEMBER; roles above are assigned afterwards. If the policy demands
     * age assurance the person does not have, or their proofs warrant a cap
     * under the hub's attestation rules, they are admitted with that cap and
     * told why, rather than refused: a guest can still use the hub.
     */
    public Membership admit(String actorUserId, String subjectUserId, Role requested, AgeAssurance assurance,
                            AttestationWallet wallet, AttestationVerifier verifier, boolean refreshPlausible) {
        Instant now = runtime.now();
        Membership actor = actorWith(actorUserId, Permission.APPROVE_MEMBER);
        if (actor == null || subjectUserId == null || hub.getRoster().membershipOf(subjectUserId).isPresent()) {
            return null;
        }
        Role role = (requested == null ? Role.MEMBER : requested).cappedAt(Role.MEMBER);
        Membership m = new Membership(subjectUserId, hub.getHubId(), role).joinedAt(now);
        m.setAdmittedByUserId(actorUserId);
        HubPolicy policy = hub.getPolicy();
        if (policy != null && !policy.permitsFullMembership(assurance, now)) {
            m.applyRestriction(new Restriction(m.getMembershipId(), Restriction.Reason.AGE_NOT_ASSURED,
                    Restriction.Scope.THIS_HUB, Role.GUEST).appliedAt(now).appliedBy(actorUserId));
        }
        if (verifier != null) {
            Restriction cap = verifier.evaluate(wallet, m.getMembershipId(), refreshPlausible, now);
            if (cap != null) {
                m.applyRestriction(cap);
            }
        }
        hub.getRoster().add(m);
        runtime.log(HubLog.EventType.MEMBER_ADMITTED, actorUserId, subjectUserId, role.name(), now);
        return m;
    }

    /**
     * Admits or renews a walk-in guest on a presence proof this hub issued.
     * No actor: presence on the hub's own network is the vouching.
     */
    public Membership admitGuestByPresence(String deviceKeyFingerprint, PresenceProof proof) {
        Instant now = runtime.now();
        if (hub.getPolicy() == null || !hub.getPolicy().isAllowGuests() || runtime.getHubKey() == null
                || proof == null || !proof.verify(runtime.getHubKey().publicKey(), deviceKeyFingerprint, now)) {
            return null;
        }
        Optional<Membership> existing = hub.getRoster().membershipOf(deviceKeyFingerprint);
        if (existing.isPresent()) {
            if (existing.get().isGuest()) {
                existing.get().recordPresence(proof);
            }
            return existing.get();
        }
        Membership m = new Membership(deviceKeyFingerprint, hub.getHubId(), Role.GUEST).joinedAt(now);
        m.recordPresence(proof);
        hub.getRoster().add(m);
        runtime.log(HubLog.EventType.GUEST_ADMITTED_BY_PRESENCE, null, deviceKeyFingerprint, null, now);
        return m;
    }

    /** Re-checks a member's age assurance and lifts the cap if it now satisfies policy. */
    public boolean acceptAgeAssurance(String actorUserId, String subjectUserId, AgeAssurance assurance) {
        Instant now = runtime.now();
        Membership actor = actorWith(actorUserId, Permission.APPROVE_MEMBER);
        Membership subject = member(subjectUserId);
        if (actor == null || subject == null || hub.getPolicy() == null
                || !hub.getPolicy().permitsFullMembership(assurance, now)) {
            return false;
        }
        boolean lifted = false;
        for (Restriction r : subject.activeRestrictions(now)) {
            if (r.getReason() == Restriction.Reason.AGE_NOT_ASSURED) {
                lifted |= r.lift(actorUserId, "age assurance accepted");
            }
        }
        if (lifted) {
            // Method only: no document, no date of birth, nothing about the person.
            runtime.log(HubLog.EventType.AGE_ASSURANCE_ACCEPTED, actorUserId, subjectUserId,
                    assurance.getMethod().name(), now);
        }
        return lifted;
    }

    /**
     * Changes a role. ASSIGN_ROLE, which only admins hold. An admin cannot be
     * demoted if they are the last one while others remain.
     */
    public boolean assignRole(String actorUserId, String subjectUserId, Role newRole) {
        Instant now = runtime.now();
        Membership actor = actorWith(actorUserId, Permission.ASSIGN_ROLE);
        Membership subject = member(subjectUserId);
        if (actor == null || subject == null || newRole == null || newRole == subject.getRole()) {
            return false;
        }
        if (subject.isAdmin() && newRole != Role.ADMIN && !hub.getRoster().canRelinquishAdmin(subjectUserId)) {
            return false;
        }
        if (!subject.setRole(newRole, actorUserId)) {
            return false;
        }
        runtime.log(HubLog.EventType.ROLE_ASSIGNED, actorUserId, subjectUserId, newRole.name(), now);
        return true;
    }

    /** Applies a restriction. A moderator power, never on an equal or higher role unless an admin acts. */
    public boolean restrict(String actorUserId, String subjectUserId, Restriction restriction) {
        Instant now = runtime.now();
        Membership actor = actorWith(actorUserId, Permission.REMOVE_MEMBER);
        Membership subject = member(subjectUserId);
        if (actor == null || subject == null || restriction == null || !outranks(actor, subject)) {
            return false;
        }
        restriction.appliedBy(actorUserId);
        subject.applyRestriction(restriction);
        runtime.log(HubLog.EventType.RESTRICTION_APPLIED, actorUserId, subjectUserId,
                restriction.getReason() == null ? null : restriction.getReason().name(), now);
        return true;
    }

    public boolean liftRestriction(String actorUserId, String subjectUserId, String restrictionId,
                                   String justification) {
        Instant now = runtime.now();
        Membership actor = actorWith(actorUserId, Permission.REMOVE_MEMBER);
        Membership subject = member(subjectUserId);
        if (actor == null || subject == null || actorUserId.equals(subjectUserId)
                || !subject.liftRestriction(restrictionId, actorUserId, justification)) {
            return false;
        }
        runtime.log(HubLog.EventType.RESTRICTION_LIFTED, actorUserId, subjectUserId, null, now);
        return true;
    }

    /** Removes a member. REMOVE_MEMBER, on a lower role, never the last admin. Their imported skills go too. */
    public boolean remove(String actorUserId, String subjectUserId) {
        Instant now = runtime.now();
        Membership actor = actorWith(actorUserId, Permission.REMOVE_MEMBER);
        Membership subject = member(subjectUserId);
        if (actor == null || subject == null || !outranks(actor, subject)
                || (subject.isAdmin() && hub.getRoster().adminCount() <= 1)) {
            return false;
        }
        hub.getRoster().remove(subjectUserId, null, null);
        hub.getSkillsLayer().purgeMember(subjectUserId);
        runtime.log(HubLog.EventType.MEMBER_REMOVED, actorUserId, subjectUserId, null, now);
        return true;
    }

    /** Leaves. The last admin cannot leave while anyone else remains. */
    public boolean leave(String userId) {
        Instant now = runtime.now();
        Membership m = member(userId);
        if (m == null || (m.isAdmin() && !hub.getRoster().canRelinquishAdmin(userId))) {
            return false;
        }
        hub.getRoster().remove(userId, null, null);
        hub.getSkillsLayer().purgeMember(userId);
        runtime.log(HubLog.EventType.MEMBER_LEFT, userId, null, null, now);
        return true;
    }

    /** The full roster, for VIEW_MEMBERS. Viewing is itself logged. */
    public List<Membership> viewRoster(String actorUserId) {
        Membership actor = actorWith(actorUserId, Permission.VIEW_MEMBERS);
        if (actor == null) {
            return List.of();
        }
        runtime.log(HubLog.EventType.ROSTER_VIEWED, actorUserId, null, "roster", runtime.now());
        return hub.getRoster().getMemberships();
    }

    /** The hub log, for VIEW_LOG. Viewing is itself logged. */
    public List<HubLog.Entry> viewLog(String actorUserId) {
        Membership actor = actorWith(actorUserId, Permission.VIEW_LOG);
        if (actor == null) {
            return List.of();
        }
        runtime.log(HubLog.EventType.ROSTER_VIEWED, actorUserId, null, "log", runtime.now());
        return hub.getLog().getEntries();
    }

    // --- policy -----------------------------------------------------------

    /**
     * Changes policy through a copy: the change is applied, validated and only
     * then installed. Returns the validation issues, which admins see and
     * members are told about through the disclosure. Null if not permitted.
     */
    public List<String> changePolicy(String actorUserId, Consumer<HubPolicy> change) {
        Membership actor = actorWith(actorUserId, Permission.EDIT_HUB_POLICY);
        if (actor == null || hub.getPolicy() == null) {
            return null;
        }
        HubPolicy next = hub.getPolicy().copy();
        change.accept(next);
        List<String> issues = next.validate();
        hub.setPolicy(next);
        runtime.log(HubLog.EventType.POLICY_CHANGED, actorUserId, null, issues.size() + " issue(s)", runtime.now());
        return issues;
    }

    // --- resources and skills ---------------------------------------------

    public Optional<HubResource> addResource(String actorUserId, HubResource resource) {
        Membership actor = actorWith(actorUserId, Permission.MANAGE_RESOURCES);
        if (actor == null) {
            return Optional.empty();
        }
        Optional<HubResource> added = hub.getSkillsLayer().addResource(resource, runtime.getCensor());
        if (added.isPresent()) {
            runtime.log(HubLog.EventType.RESOURCE_ADDED, actorUserId, resource.getResourceId(), null, runtime.now());
            rederiveHubSkills(actorUserId, runtime.now());
        }
        return added;
    }

    public boolean removeResource(String actorUserId, String resourceId) {
        Membership actor = actorWith(actorUserId, Permission.MANAGE_RESOURCES);
        if (actor == null || !hub.getSkillsLayer().removeResource(resourceId)) {
            return false;
        }
        runtime.log(HubLog.EventType.RESOURCE_REMOVED, actorUserId, resourceId, null, runtime.now());
        rederiveHubSkills(actorUserId, runtime.now());
        return true;
    }

    void rederiveHubSkills(String actorUserId, Instant now) {
        if (runtime.getMatchmaker() != null && runtime.getCensor() != null) {
            int n = hub.getSkillsLayer().deriveHubSkills(runtime.getMatchmaker(), runtime.getCensor()).size();
            runtime.log(HubLog.EventType.HUB_SKILLS_DERIVED, actorUserId, null, String.valueOf(n), now);
        }
    }

    /** A member or guest logs use of a resource. No resource or user in the log detail. */
    public ResourceInteraction recordInteraction(String userId, String resourceId, String note) {
        Instant now = runtime.now();
        Membership m = member(userId);
        if (m == null || !m.can(Permission.RECORD_RESOURCE_USE, hub.getStanding()) || !m.hasValidPresence(now)) {
            return null;
        }
        ResourceInteraction i = hub.getSkillsLayer().recordInteraction(userId, resourceId, note,
                runtime.getCensor(), now);
        if (i != null) {
            runtime.log(HubLog.EventType.RESOURCE_INTERACTION_RECORDED, null, null, null, now);
        }
        return i;
    }

    /**
     * An admin verifies an interaction. Returns the credentials to deliver to
     * the user's device, or null when they cannot be issued yet (the hub is
     * not authenticated, or no credential scheme is bound). The admin may not
     * verify their own interaction.
     */
    public List<SkillCredential> verifyInteraction(String actorUserId, String interactionId,
                                                   UserSkill.Proficiency proficiency) {
        Instant now = runtime.now();
        Membership actor = actorWith(actorUserId, Permission.VERIFY_EARNED_SKILL);
        if (actor == null) {
            return null;
        }
        for (ResourceInteraction i : hub.getSkillsLayer().getPendingInteractions()) {
            if (i.getInteractionId().equals(interactionId) && actorUserId.equals(i.getUserKeyFingerprint())) {
                return null;
            }
        }
        List<List<byte[]>> rings = runtime.currentRings();
        List<SkillCredential> issued = hub.getSkillsLayer().verifyInteraction(interactionId, actorUserId, proficiency,
                hub.getStanding(), runtime.getCredentialScheme(), rings.isEmpty() ? List.of() : rings.get(0),
                runtime.getHubKey(), now);
        if (issued != null && !issued.isEmpty()) {
            runtime.log(HubLog.EventType.SKILL_EARNED_VERIFIED, actorUserId, null, null, now);
        }
        return issued;
    }

    public boolean rejectInteraction(String actorUserId, String interactionId, String reason) {
        Membership actor = actorWith(actorUserId, Permission.VERIFY_EARNED_SKILL);
        if (actor == null || !hub.getSkillsLayer().rejectInteraction(interactionId, actorUserId, reason)) {
            return false;
        }
        runtime.log(HubLog.EventType.SKILL_EARNED_REJECTED, actorUserId, null, null, runtime.now());
        return true;
    }

    /** A member presents credentials. Logged as a count only. */
    public int presentCredentials(String userId, List<SkillCredential> credentials) {
        Instant now = runtime.now();
        Membership m = member(userId);
        if (m == null || !m.can(Permission.PRESENT_SKILL_CREDENTIALS, hub.getStanding())) {
            return 0;
        }
        int n = hub.getSkillsLayer().importPresented(userId, credentials, runtime.currentRings(),
                runtime.getCredentialScheme(), runtime.getMatchmaker(), now, false);
        if (n > 0) {
            runtime.log(HubLog.EventType.SKILL_CREDENTIAL_IMPORTED, null, null, String.valueOf(n), now);
        }
        return n;
    }

    // --- moderation -------------------------------------------------------

    /**
     * Records an outcome about a member, decided by the actor. The outcome must
     * cite log entries as evidence and expire (see {@link ModerationOutcome}).
     * A removal or suspension also caps the member here at once.
     */
    public boolean recordOutcome(String actorUserId, ModerationOutcome outcome) {
        Instant now = runtime.now();
        Membership actor = actorWith(actorUserId, Permission.REMOVE_MEMBER);
        if (actor == null || outcome == null || !actorUserId.equals(outcome.getDecidedByUserId())
                || actorUserId.equals(outcome.getSubjectKeyFingerprint())) {
            return false;
        }
        Membership subject = member(outcome.getSubjectKeyFingerprint());
        if (subject != null && !outranks(actor, subject)) {
            return false;
        }
        hub.getModerationOutcomes().add(outcome);
        if (subject != null && outcome.getKind() != ModerationOutcome.Kind.WARNING) {
            subject.applyRestriction(new Restriction(subject.getMembershipId(), Restriction.Reason.MODERATION_ACTION,
                    Restriction.Scope.THIS_HUB, Role.GUEST).appliedAt(now).appliedBy(actorUserId)
                    .expiring(outcome.getExpiresAt()));
        }
        runtime.log(HubLog.EventType.MODERATION_OUTCOME_RECORDED, actorUserId, outcome.getSubjectKeyFingerprint(),
                outcome.getKind().name(), now);
        return true;
    }

    public boolean appealOutcome(String subjectUserId, String outcomeId) {
        for (ModerationOutcome o : hub.getModerationOutcomes()) {
            if (o.getOutcomeId().equals(outcomeId) && o.lodgeAppeal(subjectUserId)) {
                runtime.log(HubLog.EventType.MODERATION_OUTCOME_APPEALED, subjectUserId, outcomeId, null,
                        runtime.now());
                return true;
            }
        }
        return false;
    }

    /** Overturns an outcome and lifts the cap it caused. Not by the moderator who decided it. */
    public boolean overturnOutcome(String actorUserId, String outcomeId, String justification) {
        Instant now = runtime.now();
        Membership actor = actorWith(actorUserId, Permission.REMOVE_MEMBER);
        if (actor == null) {
            return false;
        }
        for (ModerationOutcome o : hub.getModerationOutcomes()) {
            if (o.getOutcomeId().equals(outcomeId) && o.overturn(actorUserId, justification)) {
                Membership subject = member(o.getSubjectKeyFingerprint());
                if (subject != null) {
                    for (Restriction r : subject.activeRestrictions(now)) {
                        if (r.getReason() == Restriction.Reason.MODERATION_ACTION
                                && java.util.Objects.equals(r.getExpiresAt(), o.getExpiresAt())) {
                            r.lift(actorUserId, justification);
                        }
                    }
                }
                runtime.log(HubLog.EventType.MODERATION_OUTCOME_OVERTURNED, actorUserId, outcomeId, null, now);
                return true;
            }
        }
        return false;
    }

    // --- integrity and standing -------------------------------------------

    /** Runs the local censor check and records the result, logging changes. */
    public CensorIntegrity checkCensorIntegrity(Instant now) {
        CensorIntegrity before = hub.getCensorIntegrity();
        CensorIntegrity after = CensorIntegrity.checkLocal(runtime.getCensor(), hub.getPolicy(), now);
        recordIntegrity(before, after, now);
        return after;
    }

    /** A replica advertised a different censor during sync. */
    public CensorIntegrity onPeerDivergence(String peerPin, String peerEndpointId) {
        Instant now = runtime.now();
        String expected = hub.getPolicy() == null ? null : hub.getPolicy().getRequiredCensorPinHash();
        CensorIntegrity after = CensorIntegrity.peerDivergence(expected, peerPin, peerEndpointId, now);
        recordIntegrity(hub.getCensorIntegrity(), after, now);
        return after;
    }

    private void recordIntegrity(CensorIntegrity before, CensorIntegrity after, Instant now) {
        hub.setCensorIntegrity(after);
        boolean wasFlagged = before != null && before.requiresRestriction();
        if (after.requiresRestriction() && !wasFlagged) {
            runtime.log(HubLog.EventType.CENSOR_INTEGRITY_FAILED, null, null, after.getState().name(), now);
            runtime.log(HubLog.EventType.HUB_FLAGGED_COMPROMISED, null, null, null, now);
        } else if (wasFlagged && after.isVerified()) {
            runtime.log(HubLog.EventType.HUB_FLAG_CLEARED, null, null, null, now);
        }
    }

    /** Installs a standing computed by WebOfTrust (stage 4), logging a change of state. */
    public void updateStanding(HubStanding standing) {
        HubStanding before = hub.getStanding();
        hub.setStanding(standing);
        if (before == null || before.getState() != standing.getState()) {
            runtime.log(HubLog.EventType.HUB_STANDING_CHANGED, null, null, standing.getState().name(), runtime.now());
        }
    }

    // --- retention and duress ---------------------------------------------

    /** What one retention pass removed. */
    public record Pruned(int logEntries, int censorLeaves, int interactions, int meetingRecords, int restrictions,
                         int outcomes) {
    }

    /**
     * Applies every retention window. Expected to run daily, not optional. The
     * censor log's open day is closed first, so every day has a head.
     */
    public Pruned applyRetention() {
        Instant now = runtime.now();
        HubPolicy p = hub.getPolicy();
        int logDays = p == null ? 30 : p.getLogRetentionDays();
        int fortnight = p == null ? HubPolicy.MEETING_REQUEST_RETENTION_DAYS : p.getMeetingRequestRetentionDays();
        int logEntries = hub.getLog().prune(logDays, now);
        int leaves = 0;
        if (hub.getCensorLog() != null && runtime.getHubKey() != null) {
            java.time.LocalDate yesterday = java.time.LocalDate.ofInstant(now, java.time.ZoneOffset.UTC).minusDays(1);
            hub.getCensorLog().closeThrough(yesterday, runtime.getHubKey(), now);
            leaves = hub.getCensorLog().prune(fortnight, now);
        }
        int interactions = hub.getSkillsLayer().prune(fortnight, now);
        int meetings = hub.getMeetings().prune(fortnight, now);
        int restrictions = 0;
        Instant cutoff = now.minus(Duration.ofDays(logDays));
        for (Membership m : hub.getRoster().getMemberships()) {
            restrictions += m.pruneRestrictions(cutoff, now);
        }
        int before = hub.getModerationOutcomes().size();
        hub.getModerationOutcomes().removeIf(o -> !o.isActive(now) && o.getExpiresAt().isBefore(cutoff));
        int outcomes = before - hub.getModerationOutcomes().size();
        runtime.log(HubLog.EventType.LOG_PRUNED, null, null, String.valueOf(logEntries), now);
        return new Pruned(logEntries, leaves, interactions, meetings, restrictions, outcomes);
    }

    /**
     * Duress wipe of in-memory hub data. Admins only, and only where policy
     * allows. The persistent store must be crypto-shredded too
     * ({@code EncryptedStore.shred}), because deleted rows survive in flash.
     */
    public boolean panicWipe(String actorUserId) {
        Membership actor = member(actorUserId);
        if (actor == null || !actor.isAdmin() || hub.getPolicy() == null || !hub.getPolicy().isAllowPanicWipe()) {
            return false;
        }
        hub.getLog().wipe();
        if (hub.getCensorLog() != null) {
            hub.getCensorLog().wipe();
        }
        hub.getSkillsLayer().wipe();
        hub.getMeetings().wipe();
        hub.getModerationOutcomes().clear();
        hub.setRoster(new Roster());
        return true;
    }

    // --- helpers ----------------------------------------------------------

    private Membership member(String userId) {
        return userId == null ? null : hub.getRoster().membershipOf(userId).orElse(null);
    }

    /** The actor's membership if they hold the permission under the hub's standing, else null. */
    private Membership actorWith(String userId, Permission permission) {
        Membership m = member(userId);
        return m != null && m.can(permission, hub.getStanding()) ? m : null;
    }

    /** Admins act on anyone; others only on lower roles, and never on themselves. */
    private boolean outranks(Membership actor, Membership subject) {
        if (actor.getUserId().equals(subject.getUserId())) {
            return false;
        }
        return actor.isAdmin() || actor.getRole().compareTo(subject.getRole()) > 0;
    }

    public Hub getHub() {
        return hub;
    }
}
