package org.shalim.hub;

import java.time.Duration;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.List;
import org.shalim.crypto.SoftwareSigner;
import org.shalim.identity.Membership;
import org.shalim.identity.Restriction;
import org.shalim.identity.Role;
import org.shalim.ml.Match;
import org.shalim.query.HubQuery;
import org.shalim.query.QueryResult;
import org.shalim.skills.ResourceInteraction;
import org.shalim.skills.SkillCredential;
import org.shalim.skills.SkillProfile;
import org.shalim.skills.UserSkill;
import org.shalim.testing.Check;
import org.shalim.testing.HubFixture;

/** Creation, roles, the query pipeline, earning skills and retention, end to end on stub models. */
public final class HubCoreTest {

    private HubCoreTest() {
    }

    private static QueryResult ask(HubFixture f, String who, String question) {
        return new QueryService(f.hub, f.runtime).ask(new HubQuery(f.hub.getHubId(), who, question).withMaxMatches(5));
    }

    public static void testCreationScreensResourcesDerivesSkillsAndLogs() {
        HubFixture f = new HubFixture();
        Check.equal(2, f.hub.getSkillsLayer().getResources().size(), "the blocked resource was refused");
        List<String> terms = f.hub.getSkillsLayer().getHubSkills().stream().map(s -> s.getTaxonomyTerm()).toList();
        Check.isTrue(terms.contains("metalwork") && terms.contains("gardening"), "hub skills derived: " + terms);
        Check.equal(HubStanding.State.UNAUTHENTICATED, f.hub.getStanding().getState(), "starts unauthenticated");
        Check.isTrue(f.hub.getCensorIntegrity().isVerified(), "censor checked at creation");
        Check.isTrue(f.hub.isViable(), "complete, claimed, administered, resourced");
        Check.isTrue(f.hub.getLog().verifyChain(fp -> f.hubKey.publicKey()), "creation log verifies under the hub key");
        Check.equal(HubLog.EventType.HUB_CREATED, f.hub.getLog().getEntries().get(0).getType(), "first entry");

        HubAdministration.Created refused = HubAdministration.create(new HubAdministration.Creation("x", null,
                HubPolicy.defaultsFor(HubPolicy.Posture.COMMUNITY), new HubLocation(null, "no address"), null,
                f.admin.fingerprint(), List.of()), f.runtime);
        Check.isFalse(refused.ok(), "incomplete creation refused");
        Check.isTrue(refused.problems().size() >= 3, "with every reason: " + refused.problems());
    }

    public static void testNewHubMembersAreGuestsUntilAuthenticated() {
        HubFixture f = new HubFixture();
        String member = f.newMember(Role.MEMBER);
        QueryResult r = ask(f, member, "who can teach lathe work?");
        Check.isTrue(r.wasBlocked(), "refused");
        Check.isTrue(r.getBlockedReason().contains("hasn't been checked"), "told why: " + r.getBlockedReason());
        Check.isNull(r.getCensorReceipt(), "refused before screening, so nothing was logged about the text");
        Check.isFalse(ask(f, f.admin.fingerprint(), "who can teach lathe work?").wasBlocked(), "admins can still query");
        f.authenticate();
        Check.isFalse(ask(f, member, "who can teach lathe work?").wasBlocked(), "members can once authenticated");
    }

    public static void testScreeningCommitsEveryDecisionWithAReceipt() {
        HubFixture f = new HubFixture();
        f.authenticate();
        String member = f.newMember(Role.MEMBER);
        QueryResult ok = ask(f, member, "anyone with seeds to share?");
        QueryResult blocked = ask(f, member, "where to get a blockme");
        QueryResult held = ask(f, member, "holdme please");
        Check.isTrue(blocked.wasBlocked() && blocked.getCensorReceipt() != null, "refused, with a receipt");
        Check.isTrue(held.isHeld() && held.getCensorReceipt() != null, "held, with a receipt");
        Check.notNull(ok.getCensorReceipt(), "answered, with a receipt");
        LocalDate day = LocalDate.ofInstant(f.clock.instant(), ZoneOffset.UTC);
        CensorDecisionLog.SignedTreeHead head = f.hub.getCensorLog().close(day, f.hubKey, f.clock.instant());
        for (QueryResult r : List.of(ok, blocked, held)) {
            CensorDecisionLog.Receipt rc = r.getCensorReceipt();
            Check.isTrue(rc.verify(f.hubKey.publicKey()), "receipt signed by the hub");
            Check.isTrue(f.hub.getCensorLog().proveInclusion(day, rc.getLeafIndex())
                    .verify(rc.getLeafHash(), head.getRootHash()), "and in the day's tree");
        }
    }

    public static void testMatchesNeverIncludeHiddenGuestOrRestrictedMembers() {
        HubFixture f = new HubFixture();
        f.authenticate();
        String asker = f.newMember(Role.MEMBER);
        String visible = f.newMember(Role.MEMBER);
        String hidden = f.newMember(Role.MEMBER);
        String restricted = f.newMember(Role.MEMBER);
        String adminsOnly = f.newMember(Role.MEMBER);
        HubAdministration admin = f.admin();
        for (String who : List.of(visible, hidden, restricted, adminsOnly)) {
            earn(f, who, "Lathe");
        }
        f.hub.getRoster().membershipOf(hidden).get().setVisibility(Membership.Visibility.HIDDEN);
        f.hub.getRoster().membershipOf(adminsOnly).get().setVisibility(Membership.Visibility.ADMINS_ONLY);
        Membership r = f.hub.getRoster().membershipOf(restricted).get();
        admin.restrict(f.admin.fingerprint(), restricted, new Restriction(r.getMembershipId(),
                Restriction.Reason.MODERATION_ACTION, Restriction.Scope.THIS_HUB, Role.GUEST)
                .appliedAt(f.clock.instant()));
        List<String> people = people(ask(f, asker, "lathe metalwork help"));
        Check.equal(List.of(visible), people, "only the visible, unrestricted member");
        List<String> forAdmin = people(ask(f, f.admin.fingerprint(), "lathe metalwork help"));
        Check.isTrue(forAdmin.contains(adminsOnly) && !forAdmin.contains(hidden), "admins see ADMINS_ONLY, never HIDDEN");
    }

    private static List<String> people(QueryResult r) {
        return r.getMatches().stream().filter(m -> m.getKind() == Match.Kind.MEMBER).map(Match::getTargetId).toList();
    }

    /** A member uses a resource, an admin verifies it, the credential is presented back. */
    private static void earn(HubFixture f, String who, String resourceName) {
        HubAdministration admin = f.admin();
        String resourceId = f.hub.getSkillsLayer().getResources().stream()
                .filter(x -> x.getName().equals(resourceName)).findFirst().get().getResourceId();
        ResourceInteraction i = admin.recordInteraction(who, resourceId, "turned a bowl");
        List<SkillCredential> creds = admin.verifyInteraction(f.admin.fingerprint(), i.getInteractionId(),
                UserSkill.Proficiency.PRACTISED);
        SkillProfile profile = new SkillProfile(who);
        UserSkill skill = profile.store(creds.get(0));
        profile.setPresented(f.hub.getHubId(), List.of(skill.getUserSkillId()));
        Check.equal(1, admin.presentCredentials(who, profile.presentTo(f.hub.getHubId(), f.clock.instant())),
                "imported");
    }

    public static void testEarningWaitsForAuthenticationAndNothingIsLost() {
        HubFixture f = new HubFixture();
        String member = f.newMember(Role.MEMBER);
        HubAdministration admin = f.admin();
        String lathe = f.hub.getSkillsLayer().getResources().get(0).getResourceId();
        ResourceInteraction i = admin.recordInteraction(member, lathe, "first go");
        Check.notNull(i, "a capped member can still log use");
        Check.isNull(admin.verifyInteraction(f.admin.fingerprint(), i.getInteractionId(),
                UserSkill.Proficiency.INTRODUCED), "an unauthenticated hub cannot sign");
        Check.equal(1, f.hub.getSkillsLayer().getPendingInteractions().size(), "still pending");
        f.authenticate();
        List<SkillCredential> creds = admin.verifyInteraction(f.admin.fingerprint(), i.getInteractionId(),
                UserSkill.Proficiency.INTRODUCED);
        Check.equal("metalwork", creds.get(0).getTaxonomyTerm(), "credential carries the shared term, not the label");
        Check.equal(0, f.hub.getSkillsLayer().getPendingInteractions().size(), "decided and dropped");
        Check.equal(1, admin.presentCredentials(member, List.of(creds.get(0), creds.get(0))),
                "the same credential twice imports once");
        Check.isNull(admin.verifyInteraction(member, "anything", UserSkill.Proficiency.CAN_TEACH),
                "members cannot verify");
    }

    public static void testRoleInvariants() {
        HubFixture f = new HubFixture();
        f.authenticate();
        HubAdministration admin = f.admin();
        String mod = f.newMember(Role.MODERATOR);
        String member = f.newMember(Role.MEMBER);
        Check.isFalse(admin.assignRole(f.admin.fingerprint(), f.admin.fingerprint(), Role.MEMBER),
                "the last admin cannot step down while others remain");
        Check.isFalse(admin.leave(f.admin.fingerprint()), "nor leave");
        Check.isFalse(admin.remove(mod, f.admin.fingerprint()), "a moderator cannot remove an admin");
        Check.isFalse(admin.assignRole(mod, member, Role.MODERATOR), "moderators do not assign roles");
        Check.isTrue(admin.remove(mod, member), "a moderator can remove a member");
        Check.equal(Role.MEMBER, admin.admit(f.admin.fingerprint(), "x", Role.ADMIN, null, null, null, false).getRole(),
                "nobody is admitted as admin");
        Check.isTrue(admin.viewRoster(mod).size() >= 2, "moderators can see the roster");
        Check.equal(HubLog.EventType.ROSTER_VIEWED,
                f.hub.getLog().getEntries().get(f.hub.getLog().getEntries().size() - 1).getType(),
                "and that is logged");
        Check.equal(0, admin.viewRoster(SoftwareSigner.generate().fingerprint()).size(), "strangers see nothing");
    }

    public static void testIntegrityFailureStopsQueriesAndIsLogged() {
        HubFixture f = new HubFixture();
        f.authenticate();
        String member = f.newMember(Role.MEMBER);
        f.censor.simulateTampering();
        f.admin().checkCensorIntegrity(f.clock.instant());
        Check.isTrue(f.hub.getCensorIntegrity().requiresRestriction(), "flagged");
        Check.isTrue(ask(f, member, "seeds?").getBlockedReason().contains("paused"), "queries paused");
        Check.isTrue(f.hub.getLog().byType(HubLog.EventType.HUB_FLAGGED_COMPROMISED).size() == 1, "logged once");
    }

    public static void testQueueForReviewHoldsResultsWhenTheCensorIsMissing() {
        HubFixture f = new HubFixture();
        f.authenticate();
        String member = f.newMember(Role.MEMBER);
        f.censor.unload();
        f.admin().checkCensorIntegrity(f.clock.instant());
        QueryResult r = ask(f, member, "seeds?");
        Check.isTrue(r.isHeld(), "COMMUNITY policy queues rather than answering unscreened");
        Check.notNull(r.getCensorReceipt(), "and still commits a leaf");
    }

    public static void testRateLimit() {
        HubFixture f = new HubFixture();
        f.authenticate();
        String member = f.newMember(Role.MEMBER);
        QueryService qs = new QueryService(f.hub, f.runtime);
        for (int i = 0; i < QueryService.HOURLY_LIMIT; i++) {
            Check.isFalse(qs.ask(new HubQuery(f.hub.getHubId(), member, "seeds " + i)).wasBlocked(), "within limit");
        }
        Check.isTrue(qs.ask(new HubQuery(f.hub.getHubId(), member, "one more")).getBlockedReason().contains("a lot"),
                "eleventh in an hour refused");
        f.clock.advance(Duration.ofHours(1).plusSeconds(1));
        Check.isFalse(qs.ask(new HubQuery(f.hub.getHubId(), member, "later")).wasBlocked(), "window rolls");
    }

    public static void testGuestsByPresence() {
        HubFixture f = new HubFixture();
        f.authenticate();
        String device = SoftwareSigner.generate().fingerprint();
        PresenceProof proof = f.hub.getNetwork().issuePresenceProof(device, f.hub.getPolicy(), f.hubKey,
                f.clock.instant());
        Membership guest = f.admin().admitGuestByPresence(device, proof);
        Check.isTrue(guest.isGuest(), "admitted as a guest");
        Check.notNull(f.admin().recordInteraction(device, f.hub.getSkillsLayer().getResources().get(1).getResourceId(),
                null), "guests can log resource use");
        Check.isTrue(ask(f, device, "seeds?").getBlockedReason().startsWith("Guests can use"), "but not search people");
        f.clock.advance(Duration.ofMinutes(f.hub.getPolicy().getGuestPresenceTtlMinutes() + 1L));
        Check.isNull(f.admin().recordInteraction(device, f.hub.getSkillsLayer().getResources().get(1).getResourceId(),
                null), "and nothing once their presence lapses");
        Check.isNull(f.admin().admitGuestByPresence(SoftwareSigner.generate().fingerprint(), proof),
                "a proof works only for the device it names");
    }

    public static void testRetentionAndPanicWipe() {
        HubFixture f = new HubFixture();
        f.authenticate();
        String member = f.newMember(Role.MEMBER);
        ask(f, member, "seeds?");
        f.clock.advance(Duration.ofDays(40));
        HubAdministration.Pruned p = f.admin().applyRetention();
        Check.isTrue(p.logEntries() > 0, "old log entries pruned");
        Check.isTrue(p.censorLeaves() > 0, "old censor leaves pruned");
        Check.isTrue(f.hub.getLog().verifyChain(fp -> f.hubKey.publicKey()), "chain re-anchored and still verifies");
        Check.isFalse(f.admin().panicWipe(member), "members cannot wipe");
        Check.isTrue(f.admin().panicWipe(f.admin.fingerprint()), "admins can, where policy allows");
        Check.equal(0, f.hub.getLog().getEntries().size(), "log gone");
        Check.equal(0, f.hub.getRoster().getMemberships().size(), "roster gone");
    }
}
