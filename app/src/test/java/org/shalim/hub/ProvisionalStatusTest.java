package org.shalim.hub;

import java.time.Duration;
import java.time.Instant;
import org.shalim.identity.Permission;
import org.shalim.identity.Role;
import org.shalim.testing.Check;
import org.shalim.testing.HubFixture;

public final class ProvisionalStatusTest {

    private ProvisionalStatusTest() {
    }

    private static final Instant T0 = HubFixture.T0;
    private static final double LAT = 50.8558;
    private static final double LON = 0.5806;

    private static HubStanding at(ProvisionalStatus p, Instant now) {
        return HubStanding.compute(0, 0, 0, null, false, HubPolicy.UnlockBasis.INBOUND_REQUIRED, p, now);
    }

    public static void testANewHubAloneIsProvisionalForAtMostNinetyDays() {
        ProvisionalStatus p = new ProvisionalStatus(T0, LAT, LON);
        HubStanding s = at(p, T0.plus(Duration.ofDays(10)));
        Check.equal(HubStanding.State.PROVISIONAL, s.getState(), "provisional with no certified hub near");
        Check.isNull(s.roleCapFor(new org.shalim.identity.Membership("m", "h", Role.MEMBER)), "members can query");
        Check.isFalse(s.issuesPortableCredentials(), "but it vouches for no one elsewhere");
        Check.isFalse(s.listedBeyondOwnArea(), "and is not listed beyond its area");
        Check.equal("This hub hasn't been checked by another hub yet.", s.explain(), "shown as not yet checked");
        Check.equal(HubStanding.State.UNAUTHENTICATED, at(p, T0.plus(Duration.ofDays(90))).getState(),
                "the absolute cap: guest-only after 90 days");
    }

    public static void testOnlyACertifiedHubWithinTwentyMilesStartsTheClock() {
        ProvisionalStatus p = new ProvisionalStatus(T0, LAT, LON);
        Instant seen = T0.plus(Duration.ofDays(20));
        Check.isFalse(p.observe(new ProvisionalStatus.NearbyHub("far", 51.5072, -0.1276, true, seen)),
                "London is more than 20 miles from Hastings");
        Check.isFalse(p.observe(new ProvisionalStatus.NearbyHub("new", LAT + 0.05, LON, false, seen)),
                "an uncertified newcomer never starts it");
        Check.isTrue(p.observe(new ProvisionalStatus.NearbyHub("bex", 50.8400, 0.4700, true, seen)),
                "Bexhill, certified, starts the 30-day clock");
        Check.equal(seen.plus(Duration.ofDays(30)), p.deadline(false), "30 days from first sight");
        Check.equal(HubStanding.State.PROVISIONAL, at(p, seen.plus(Duration.ofDays(29))).getState(), "still provisional");
        Check.equal(HubStanding.State.UNAUTHENTICATED, at(p, seen.plus(Duration.ofDays(30))).getState(),
                "then guest-only until linked");
        ProvisionalStatus late = new ProvisionalStatus(T0, LAT, LON);
        late.observe(new ProvisionalStatus.NearbyHub("bex", 50.84, 0.47, true, T0.plus(Duration.ofDays(80))));
        Check.equal(T0.plus(Duration.ofDays(90)), late.deadline(false), "the peer clock never extends the cap");
        Check.equal(HubStanding.State.AUTHENTICATED, HubStanding.compute(0, 1, 0, null, false,
                HubPolicy.UnlockBasis.INBOUND_REQUIRED, late, T0.plus(Duration.ofDays(200))).getState(),
                "an inbound link ends it from any state");
    }

    public static void testANewcomerToACheckedRegionIsNeverProvisional() {
        ProvisionalStatus p = new ProvisionalStatus(T0, LAT, LON);
        p.observe(new ProvisionalStatus.NearbyHub("bex", 50.84, 0.47, true, T0.plus(Duration.ofHours(3))));
        Check.isNull(p.deadline(false), "a certified hub was already near at creation");
        Check.equal(HubStanding.State.UNAUTHENTICATED, at(p, T0.plus(Duration.ofHours(4))).getState(),
                "guest-only until linked");
    }

    public static void testLosingTheOnlyInboundLinkToRevocationGivesThirtyDays() {
        ProvisionalStatus p = new ProvisionalStatus(T0, LAT, LON);
        Instant unlocked = T0.plus(Duration.ofDays(5));
        Instant revoked = T0.plus(Duration.ofDays(100));
        p.inboundRevoked(revoked);
        HubStanding s = HubStanding.compute(0, 0, 0, unlocked, true, HubPolicy.UnlockBasis.INBOUND_REQUIRED, p,
                revoked.plus(Duration.ofDays(10)));
        Check.equal(HubStanding.State.PROVISIONAL, s.getState(), "no single peer can silence a hub");
        Check.equal(HubStanding.State.REVOKED, HubStanding.compute(0, 0, 0, unlocked, true,
                HubPolicy.UnlockBasis.INBOUND_REQUIRED, p, revoked.plus(Duration.ofDays(30))).getState(),
                "but a broken hub still loses access within a month");
        Check.equal(HubStanding.State.AUTHENTICATED, HubStanding.compute(0, 0, 0, unlocked, false,
                HubPolicy.UnlockBasis.INBOUND_REQUIRED, p, revoked.plus(Duration.ofDays(60))).getState(),
                "dormant links still fail open");
    }

    public static void testMembersDevicesDoNotTakeTheHubsWordForIt() {
        // The hub claims to be provisional long after it should be.
        HubStanding claimed = HubStanding.restore(HubStanding.State.PROVISIONAL, 0, 0, 0, null,
                T0.plus(Duration.ofDays(200)), T0.plus(Duration.ofDays(400)));
        ProvisionalStatus device = new ProvisionalStatus(T0, LAT, LON);
        HubStanding seen = ProvisionalStatus.enforce(claimed, device, T0.plus(Duration.ofDays(200)));
        Check.equal(HubStanding.State.UNAUTHENTICATED, seen.getState(), "past the 90-day cap, the device caps members");
        Check.equal(Role.GUEST, seen.roleCapFor(new org.shalim.identity.Membership("m", "h", Role.MEMBER)), "at guest");
        device.observe(new ProvisionalStatus.NearbyHub("bex", 50.84, 0.47, true, T0.plus(Duration.ofDays(10))));
        HubStanding early = ProvisionalStatus.enforce(claimed, device, T0.plus(Duration.ofDays(20)));
        Check.equal(T0.plus(Duration.ofDays(40)), early.getProvisionalUntil(), "the device holds it to the earlier date");
        HubStanding honest = HubStanding.restore(HubStanding.State.AUTHENTICATED, 0, 1, 0, T0, T0, null);
        Check.isTrue(ProvisionalStatus.enforce(honest, device, T0.plus(Duration.ofDays(500))) == honest,
                "the device never loosens or second-guesses anything else");
    }

    public static void testAProvisionalHubsMembersQueryButItIssuesNothingPortable() {
        HubFixture f = new HubFixture();
        ProvisionalStatus p = ProvisionalStatus.forHub(f.hub);
        f.admin().updateStanding(HubStanding.compute(0, 0, 0, null, false, HubPolicy.UnlockBasis.INBOUND_REQUIRED, p,
                f.clock.instant()));
        String m = f.newMember(Role.MEMBER);
        Check.isTrue(f.hub.getRoster().membershipOf(m).get().can(Permission.RUN_HUB_QUERY, f.hub.getStanding()),
                "a member can search");
        Check.isFalse(new org.shalim.attestation.AttestationIssuer(f.hub, f.hubKey).canIssue(),
                "no attestations from an unchecked hub");
    }
}
