package org.shalim.identity;

import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import org.shalim.crypto.SoftwareSigner;
import org.shalim.hub.HubPolicy;
import org.shalim.hub.HubStanding;
import org.shalim.testing.Check;

public final class RolesAndRestrictionsTest {

    private static final Instant NOW = Instant.parse("2026-11-18T10:00:00Z");

    private RolesAndRestrictionsTest() {
    }

    public static void testRolesNestAndCap() {
        Check.isTrue(Role.MEMBER.permissions().containsAll(Role.GUEST.permissions()), "member includes guest");
        Check.isTrue(Role.ADMIN.permissions().containsAll(Role.MODERATOR.permissions()), "admin includes moderator");
        Check.isFalse(Role.GUEST.permissions().contains(Permission.RUN_HUB_QUERY), "guests never query");
        Check.isFalse(Role.MEMBER.permissions().contains(Permission.VIEW_MEMBERS), "members cannot list the roster");
        Check.equal(Role.GUEST, Role.ADMIN.cappedAt(Role.GUEST), "cap lowers");
        Check.equal(Role.MEMBER, Role.MEMBER.cappedAt(Role.ADMIN), "cap never raises");
        Check.equal(Role.MODERATOR, Role.MODERATOR.cappedAt(null), "no cap");
    }

    public static void testRestrictionCapsTheRoleNotIndividualPermissions() {
        Membership m = new Membership("u", "hub-1", Role.ADMIN);
        m.applyRestriction(new Restriction(m.getMembershipId(), Restriction.Reason.MODERATION_ACTION,
                Restriction.Scope.THIS_HUB, Role.GUEST).appliedAt(NOW.minusSeconds(10)));
        Check.isFalse(m.can(Permission.ASSIGN_ROLE), "a restricted admin keeps no stray admin power");
        Check.isTrue(m.can(Permission.RECORD_RESOURCE_USE), "but can still use resources");
        Check.isTrue(m.explainDenial(Permission.RUN_HUB_QUERY).startsWith("A moderator has limited"),
                "and is told why");
        Check.isTrue(m.explainDenial(Permission.RUN_HUB_QUERY).contains("ask a moderator to review"),
                "and that it can be appealed");
    }

    public static void testHubStandingIsOneMoreCapAndExplainsItself() {
        Membership member = new Membership("u", "hub-1", Role.MODERATOR);
        Membership admin = new Membership("a", "hub-1", Role.ADMIN);
        HubStanding fresh = new HubStanding();
        Check.equal(Role.GUEST, member.effectiveRole(fresh, NOW), "unauthenticated hub caps non-admins");
        Check.equal(Role.ADMIN, admin.effectiveRole(fresh, NOW), "admins keep their role to fix it");
        Check.isTrue(member.explainDenial(Permission.REMOVE_MEMBER, fresh).contains("hasn't been checked"),
                "told it is the hub, not them");
        Check.equal(Role.GUEST, member.effectiveRole(null, NOW), "missing standing fails closed");
        HubStanding ok = HubStanding.compute(1, 0, 0, null, false, HubPolicy.UnlockBasis.ANY_DIRECTION, NOW);
        Check.equal(Role.MODERATOR, member.effectiveRole(ok, NOW), "authenticated: no cap");
    }

    public static void testStandingDerivation() {
        HubPolicy.UnlockBasis in = HubPolicy.UnlockBasis.INBOUND_REQUIRED;
        Check.equal(HubStanding.State.UNAUTHENTICATED, HubStanding.compute(3, 0, 0, null, false, in, NOW).getState(),
                "outbound links do not unlock under INBOUND_REQUIRED");
        HubStanding unlocked = HubStanding.compute(0, 1, 0, null, false, in, NOW);
        Check.equal(NOW, unlocked.getEverUnlockedAt(), "unlock recorded");
        Check.equal(HubStanding.State.AUTHENTICATED,
                HubStanding.compute(0, 0, 0, NOW, false, in, NOW.plusSeconds(60)).getState(),
                "dormant links fail open after unlock");
        Check.equal(HubStanding.State.REVOKED, HubStanding.compute(0, 0, 0, NOW, true, in, NOW).getState(),
                "only positive revocation re-locks");
        Check.isFalse(HubStanding.compute(0, 0, 0, NOW, true, in, NOW).explain().contains("revoked"),
                "members are never told another hub found fault");
    }

    public static void testLeavingTheOriginHubDischargesTheCap() {
        RegisteredUser user = new RegisteredUser(SoftwareSigner.generate(), "Sam");
        user.join("flagged-hub", Role.MEMBER);
        Membership here = user.join("library", Role.MEMBER);
        here.applyRestriction(new Restriction(here.getMembershipId(), Restriction.Reason.COMPROMISED_CENSOR,
                Restriction.Scope.FEDERATED, Role.GUEST).appliedAt(NOW.minusSeconds(5)).originatingIn("flagged-hub")
                .dischargedBy(Restriction.Discharge.LEAVE_ORIGIN_HUB));
        Check.isFalse(user.can(Permission.RUN_HUB_QUERY, "library"), "capped while in the flagged hub");
        Check.isTrue(user.leave("flagged-hub"), "left");
        Check.isTrue(user.can(Permission.RUN_HUB_QUERY, "library"),
                "the cap lifts locally, without telling any hub anything");
    }

    public static void testRestrictionScopeAndLifetime() {
        Check.throwsA(IllegalArgumentException.class, () -> new Restriction("m", Restriction.Reason.MODERATION_ACTION,
                Restriction.Scope.DEVICE_WIDE, Role.GUEST), "device-wide is never for reputation");
        HubPolicy policy = HubPolicy.defaultsFor(HubPolicy.Posture.COMMUNITY);
        Restriction federated = new Restriction("m", Restriction.Reason.MODERATION_ACTION, Restriction.Scope.FEDERATED,
                Role.GUEST).originatingIn("elsewhere");
        Check.isFalse(federated.appliesIn("library", policy), "federated caps need opt-in");
        policy.trustRestrictionsFrom("elsewhere");
        Check.isTrue(federated.appliesIn("library", policy), "honoured once trusted");
        Restriction timed = new Restriction("m", Restriction.Reason.SELF_IMPOSED, Restriction.Scope.THIS_HUB,
                Role.GUEST).appliedAt(NOW).expiring(NOW.plus(Duration.ofDays(1)));
        Check.isTrue(timed.isActive(NOW.plusSeconds(1)), "active");
        Check.isFalse(timed.isActive(NOW.plus(Duration.ofDays(1))), "expired");
        Check.isTrue(timed.isDischarged(Set.of(), NOW.plus(Duration.ofDays(2))), "expiry discharges");
        Check.isFalse(timed.lift("mod", " "), "lifting needs a reason");
        Check.isTrue(timed.lift("mod", "stepped back in"), "lifted");
        Check.isFalse(timed.isActive(NOW.plusSeconds(1)), "no longer active");
    }

    public static void testAgeAssuranceLapsesAndRanks() {
        AgeAssurance self = new AgeAssurance(AgeAssurance.Method.SELF_DECLARED, true, NOW, null);
        Check.isTrue(self.isValid(NOW.plus(Duration.ofDays(89))), "valid within 90 days");
        Check.isFalse(self.isValid(NOW.plus(Duration.ofDays(91))), "self-declaration lapses soonest");
        Check.isFalse(self.satisfies(AgeAssurance.Method.ON_DEVICE_ESTIMATION), "weaker than required");
        AgeAssurance est = new AgeAssurance(AgeAssurance.Method.ON_DEVICE_ESTIMATION, true, NOW, null);
        Check.isTrue(est.satisfies(AgeAssurance.Method.VOUCHED_BY_MEMBER), "stronger satisfies weaker");
        Check.isFalse(new AgeAssurance(AgeAssurance.Method.NONE, true).isValid(NOW), "NONE is never assurance");
        HubPolicy inst = HubPolicy.defaultsFor(HubPolicy.Posture.INSTITUTIONAL);
        Check.isFalse(inst.permitsFullMembership(self, NOW), "institutional needs more than a declaration");
        Check.isTrue(inst.permitsFullMembership(est, NOW), "estimation suffices");
    }
}
