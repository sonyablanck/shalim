package org.shalim.trust;

import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalTime;
import java.time.ZoneId;
import java.util.List;
import java.util.Random;
import org.shalim.crypto.Bytes;
import org.shalim.hub.HubPolicy;
import org.shalim.ml.CensorEngine;
import org.shalim.ml.Verdict;
import org.shalim.testing.Check;
import org.shalim.testing.TrustFixture;

public final class TrustPrimitivesTest {

    private TrustPrimitivesTest() {
    }

    public static void testNullifierSharesRevealTheSecretOnlyWhenDoubleSpent() {
        byte[] secret = EpochNullifier.newSecret();
        LocalDate day = LocalDate.of(2026, 11, 19);
        EpochNullifier one = EpochNullifier.derive(secret, "aa", day, new byte[] {1});
        EpochNullifier same = EpochNullifier.derive(secret, "aa", day, new byte[] {1});
        EpochNullifier two = EpochNullifier.derive(secret, "aa", day, new byte[] {2});
        Check.equal(one.getNullifier(), two.getNullifier(), "one nullifier per member, hub and day");
        Check.isTrue(one.sameShareAs(same), "a retransmission is the same share");
        Check.isNull(EpochNullifier.recoverSecret(one, same), "one point on a line reveals nothing");
        Check.equal(EpochNullifier.commitment(secret), EpochNullifier.commitment(EpochNullifier.recoverSecret(one, two)),
                "two points recover the secret, matching the commitment made at join");
        Check.isFalse(one.getNullifier().equals(EpochNullifier.derive(secret, "aa", day.plusDays(1), new byte[] {1})
                .getNullifier()), "a new day, a new nullifier");
        Check.isFalse(one.getNullifier().equals(EpochNullifier.derive(secret, "bb", day, new byte[] {1})
                .getNullifier()), "unlinkable across hubs");
    }

    public static void testAdminOverlapCountsWithoutNaming() {
        List<String> mine = List.of("aa01", "bb02", "cc03");
        List<String> theirs = List.of("dd04", "bb02", "cc03", "ee05");
        byte[] x = AdminOverlapCheck.newExponent();
        byte[] y = AdminOverlapCheck.newExponent();
        List<byte[]> aBlind = AdminOverlapCheck.blindOwnAdmins(mine, x);
        List<byte[]> bBlind = AdminOverlapCheck.blindOwnAdmins(theirs, y);
        Check.isFalse(Bytes.equal(aBlind.get(0), bBlind.get(0)), "blinded values differ by exponent");
        int n = AdminOverlapCheck.intersectionSize(AdminOverlapCheck.doubleBlind(bBlind, x),
                AdminOverlapCheck.doubleBlind(aBlind, y));
        Check.equal(2, n, "the target learns a count");
        int none = AdminOverlapCheck.intersectionSize(
                AdminOverlapCheck.doubleBlind(AdminOverlapCheck.blindOwnAdmins(List.of("ff"), y), x),
                AdminOverlapCheck.doubleBlind(aBlind, y));
        Check.equal(0, none, "and zero when nothing is shared");
        Check.throwsA(IllegalArgumentException.class, () -> AdminOverlapCheck.doubleBlind(List.of(new byte[256]), x),
                "elements outside the group are refused");
    }

    public static void testThirtyLeavesAFortnightIsTheBudgetWhateverTheHubSize() {
        AuditSchedule s = AuditSchedule.defaultsFor(HubPolicy.Posture.COMMUNITY);
        int total = 0;
        for (int d = 0; d < 14; d++) {
            total += s.replayDraw(d, total, 1.0, false);
        }
        Check.equal(30, total, "30 real leaves over a fortnight when every leaf is real");
        Check.isTrue(s.replayDraw(0, 0, 0.25, false) > s.replayDraw(0, 0, 1.0, false),
                "more drawn when pads dilute the tree");
        Check.isTrue(s.replayDraw(0, 0, 0.01, false) <= s.getMaxReplayDrawPerDay(), "but never past the daily cap");
        Check.equal(0, s.replayDraw(5, 30, 1.0, false), "nothing once the fortnight's budget is met");
        int small = 0;
        for (int d = 0; d < 14; d++) {
            small += s.replayDraw(d, small, 1.0, true);
        }
        Check.equal(12, small, "small hubs: the weekly sample, twice");
        // The decision's arithmetic: detection depends on the count, not the share.
        Check.isTrue(1 - Math.pow(0.9, 30) > 0.95, "30 leaves catch 10% falsification over 95% of the time");
        Check.isTrue(Math.abs((1 - Math.pow(0.95, 30)) - 0.785) < 0.01, "and 5% about 79% of the time");
    }

    public static void testPostureChangesHowNotWhether() {
        AuditSchedule hr = AuditSchedule.defaultsFor(HubPolicy.Posture.HIGH_RISK);
        AuditSchedule c = AuditSchedule.defaultsFor(HubPolicy.Posture.COMMUNITY);
        Check.equal(c.getReplayLeavesPerFortnight(), hr.getReplayLeavesPerFortnight(), "same replay budget");
        Check.isTrue(hr.isReplayBatchedWeekly(), "batched weekly over sync");
        Check.equal(0.0, hr.syntheticRatePerDay(10), "no synthetic traffic");
        Check.isTrue(hr.isEnabled(), "and audited all the same");
        Check.equal(AuditSchedule.Mode.REPLAY_ONLY, c.modeFor(1, ProberEligibility.Result.ELIGIBLE), "quiet hub");
        Check.equal(AuditSchedule.Mode.REPLAY_ONLY, c.modeFor(9, ProberEligibility.Result.ANONYMITY_SET_TOO_SMALL),
                "small hub");
        Check.equal(AuditSchedule.Mode.FULL, c.modeFor(9, ProberEligibility.Result.ELIGIBLE), "otherwise full");
        Check.equal(3.0, c.syntheticRatePerDay(100), "capped at three a day");
    }

    public static void testSyntheticTimesFallInsideTheProbersHours() {
        AuditSchedule s = AuditSchedule.defaultsFor(HubPolicy.Posture.COMMUNITY);
        AuditSchedule.ActiveHours hours = new AuditSchedule.ActiveHours(LocalTime.of(18, 0), LocalTime.of(22, 0),
                ZoneId.of("Europe/London"));
        Random rng = new Random(7);
        Instant t = Instant.parse("2026-11-19T09:00:00Z");
        for (int i = 0; i < 40; i++) {
            Instant next = s.nextSyntheticAt(t, 1.5, rng, hours);
            LocalTime local = LocalTime.ofInstant(next, ZoneId.of("Europe/London"));
            Check.isTrue(!local.isBefore(LocalTime.of(18, 0)) && local.isBefore(LocalTime.of(22, 1)),
                    "inside 18:00-22:00, got " + local);
            t = next;
        }
        Check.isNull(s.nextSyntheticAt(t, 0, rng, hours), "no rate, no probe");
    }

    public static void testOutcomesAreJudgedAgainstTheSeedNotTheOtherHub() {
        TrustProbe protectedSpeech = TrustProbe.seed("p", "naloxone", CensorEngine.Surface.HUB_QUERY,
                TrustProbe.Intent.PROTECTED_SPEECH, null);
        ProbeOutcome review = new ProbeOutcome("p", "peer", CensorEngine.Decision.REVIEW, 0.6f);
        ProbeOutcome block = new ProbeOutcome("p", "peer", CensorEngine.Decision.BLOCK, 0.95f);
        ProbeOutcome allow = new ProbeOutcome("p", "me", CensorEngine.Decision.ALLOW, 0.1f);
        Check.isTrue(review.satisfies(protectedSpeech), "held for a human is right for protected speech");
        Check.isFalse(block.satisfies(protectedSpeech), "blocking it is not");
        DifferenceScore peerMiss = ProbeScoring.score(protectedSpeech, allow, block, ProbeScoring::tokenDistance);
        Check.equal(AuditAnomaly.Attribution.PEER, peerMiss.attribution(), "the peer moved");
        Check.isTrue(peerMiss.isPeerOverBlock(), "over-blocking");
        DifferenceScore localMiss = ProbeScoring.score(protectedSpeech, block, allow, ProbeScoring::tokenDistance);
        Check.equal(AuditAnomaly.Attribution.LOCAL, localMiss.attribution(), "the audit found the auditor");
        TrustProbe supply = TrustProbe.seed("s", "x", CensorEngine.Surface.HUB_QUERY, TrustProbe.Intent.SUPPLY_SIGNAL,
                null);
        Check.isFalse(supply.sendableToPeer(), "supply probes never leave this hub");
        Check.isFalse(review.satisfies(supply), "and holding one for review is not a pass");
        Verdict device = new Verdict(CensorEngine.Decision.ALLOW, List.of(), 0.1f, "pin", Instant.now());
        DifferenceScore organic = ProbeScoring.scoreOrganic("o", device, block);
        Check.isTrue(organic.isPeerOverBlock(), "an organic question refused that the device allowed");
        Check.isTrue(ProbeScoring.scoreOrganic("o", device, review).isPeerMetExpectation(),
                "a moderator hold on an ordinary question is not counted");
        Check.isFalse(ProbeScoring.score(protectedSpeech, allow,
                ProbeOutcome.failed("p", "peer", "timeout"), null).isScoreable(), "no answer is not evidence");
    }

    public static void testTheCorpusIsPinnedAndSyntheticDrawsNeverSupply() {
        ProbeCorpus c = TrustFixture.testCorpus();
        org.shalim.crypto.SoftwareSigner release = org.shalim.crypto.SoftwareSigner.generate();
        c.signWith(release);
        Check.isTrue(c.verify(c.encode(), release.publicKey()), "verifies against its own pin");
        Check.isFalse(c.verify("other".getBytes(java.nio.charset.StandardCharsets.UTF_8), release.publicKey()),
                "and not against anything else");
        for (long seed = 0; seed < 200; seed++) {
            TrustProbe p = c.sampleSynthetic(seed, LocalDate.of(2026, 11, 19));
            Check.isTrue(p.sendableToPeer(), "never SUPPLY_SIGNAL");
        }
        List<TrustProbe> sample = c.sample(4, 1);
        Check.isTrue(sample.stream().anyMatch(p -> p.getIntent() == TrustProbe.Intent.SUPPLY_SIGNAL)
                && sample.stream().anyMatch(p -> p.getIntent() == TrustProbe.Intent.PROTECTED_SPEECH),
                "self-test samples carry both detecting intents");
        Check.isTrue(TrustFixture.testCorpus().matches(c), "same seeds, same hash");
    }

    public static void testBinomialTailIsSane() {
        Check.equal(1.0, WebOfTrust.binomialUpperTail(10, 0, 0.02), "P(X>=0) = 1");
        Check.isTrue(WebOfTrust.binomialUpperTail(20, 1, 0.02) > 0.3, "one block in twenty is unremarkable");
        Check.isTrue(WebOfTrust.binomialUpperTail(20, 5, 0.02) < 0.001, "five is not");
    }
}
