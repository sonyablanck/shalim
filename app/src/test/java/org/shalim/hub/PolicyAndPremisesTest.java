package org.shalim.hub;

import java.time.Instant;
import java.util.List;
import org.shalim.ml.stub.FixedCensor;
import org.shalim.testing.Check;

public final class PolicyAndPremisesTest {

    private PolicyAndPremisesTest() {
    }

    public static void testPostureDefaultsAreConsistentAndLooseningIsFlagged() {
        for (HubPolicy.Posture p : HubPolicy.Posture.values()) {
            Check.equal(List.of(), HubPolicy.defaultsFor(p).validate(), p + " defaults validate");
            Check.isTrue(HubPolicy.defaultsFor(p).disclosureSummary().length() > 100, p + " has a disclosure");
        }
        HubPolicy risky = HubPolicy.defaultsFor(HubPolicy.Posture.HIGH_RISK);
        risky.setLogRetentionDays(90);
        risky.setAllowGuests(true);
        risky.setPublishRestrictions(true);
        Check.isTrue(risky.validate().size() >= 3, "three loosenings flagged: " + risky.validate());
        Check.throwsA(IllegalArgumentException.class, () -> risky.setMeetingRequestRetentionDays(30),
                "the fortnight is never lengthened");
        Check.isFalse(HubPolicy.defaultsFor(HubPolicy.Posture.HIGH_RISK).isAllowGuests(), "no walk-ins under risk");
    }

    public static void testLocationIsRedactedAtTheSource() {
        HubLocation l = new HubLocation("h", "Hastings Library", "Flat 2, 13a Brassey Road, Hastings",
                HubLocation.Precision.EXACT);
        l.setLocality("Hastings");
        l.setApproxPosition(50.855812, 0.580634);
        Check.isTrue(l.publicDescriptor().contains("13a Brassey Road"), "exact shows the door");
        l.setPrecision(HubLocation.Precision.APPROXIMATE);
        Check.equal("Hastings Library, Brassey Road, Hastings", l.publicDescriptor(), "approximate: street only");
        Check.equal(50.856, l.mapPoint()[0], "rounded to ~110 m");
        l.setPrecision(HubLocation.Precision.AREA);
        Check.equal("Hastings Library, Hastings", l.publicDescriptor(), "area: locality only");
        Check.equal(50.86, l.mapPoint()[0], "rounded to ~1 km");
        l.setPrecision(HubLocation.Precision.EXACT);
        Check.equal(50.86, l.mapPoint()[0], "widening cannot recover precision that was dropped");
        l.setPrecision(HubLocation.Precision.UNLISTED);
        Check.isNull(l.publicDescriptor(), "unlisted is absent, not hidden");
        Check.isNull(l.mapPoint(), "no pin at all");
        Check.isTrue(l.isComplete(), "but still a hub with premises");
        Check.isFalse(new HubLocation("h", "Somewhere").isComplete(), "no address, no hub");
    }

    public static void testOpeningHours() {
        HubLocation l = new HubLocation("h", "L", "1 Road", HubLocation.Precision.AREA);
        l.setOpeningHours("Mon-Fri 09:00-17:00; Sat 22:00-02:00; Sun closed", "Europe/London");
        Check.isTrue(l.isOpenAt(Instant.parse("2026-11-18T10:00:00Z")), "Wednesday morning");
        Check.isFalse(l.isOpenAt(Instant.parse("2026-11-18T17:00:00Z")), "closes at five");
        Check.isTrue(l.isOpenAt(Instant.parse("2026-11-22T01:30:00Z")), "Saturday night runs past midnight");
        Check.isFalse(l.isOpenAt(Instant.parse("2026-11-22T12:00:00Z")), "Sunday closed");
        l.setOpeningHours("whenever", "Europe/London");
        Check.isFalse(l.isOpenAt(Instant.parse("2026-11-18T10:00:00Z")), "unreadable hours host nothing");
        Check.isFalse(l.hasValidOpeningHours(), "and are flagged");
    }

    public static void testCensorIntegrityModes() {
        FixedCensor censor = new FixedCensor();
        HubPolicy p = HubPolicy.defaultsFor(HubPolicy.Posture.COMMUNITY);
        CensorIntegrity unavailable = CensorIntegrity.checkLocal(censor, p, Instant.now());
        Check.equal(CensorIntegrity.State.UNAVAILABLE, unavailable.getState(), "not loaded");
        Check.isFalse(unavailable.requiresRestriction(), "a missing model is not suspicious");
        Check.isTrue(unavailable.permitsQuerying(p), "COMMUNITY queues for review");
        Check.isFalse(unavailable.permitsQuerying(HubPolicy.defaultsFor(HubPolicy.Posture.HIGH_RISK)),
                "HIGH_RISK disables queries");
        try {
            censor.load();
        } catch (Exception e) {
            throw new AssertionError(e);
        }
        Check.isTrue(CensorIntegrity.checkLocal(censor, p, Instant.now()).isVerified(), "verified");
        p.setRequiredCensorPinHash("00".repeat(32));
        CensorIntegrity wrong = CensorIntegrity.checkLocal(censor, p, Instant.now());
        Check.equal(CensorIntegrity.State.MISMATCHED, wrong.getState(), "not the required pin");
        Check.isFalse(wrong.permitsQuerying(p), "tampering is never worked around");
    }
}
