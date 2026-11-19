package org.shalim.trust;

import java.time.Duration;
import java.time.LocalDate;
import java.util.List;
import org.shalim.hub.CensorDecisionLog;
import org.shalim.hub.HubLog;
import org.shalim.hub.HubPolicy;
import org.shalim.hub.HubStanding;
import org.shalim.hub.QueryService;
import org.shalim.identity.Role;
import org.shalim.ml.CensorEngine;
import org.shalim.query.HubQuery;
import org.shalim.query.QueryResult;
import org.shalim.testing.Check;
import org.shalim.testing.HubFixture;
import org.shalim.testing.TamperableCensor;
import org.shalim.testing.TrustFixture;

public final class AuthenticationFlowTest {

    private AuthenticationFlowTest() {
    }

    /** Runs days until the link reaches the state, or fails after a limit. */
    private static void until(TrustFixture t, AuthLink.State state, int maxDays) {
        for (int i = 0; i < maxDays && t.link().getState() != state; i++) {
            t.day(70); // over two padded blocks a day: busy enough for probing (traffic band 2)
        }
        Check.equal(state, t.link().getState(), "link reached " + state);
    }

    private static long logged(HubFixture f, HubLog.EventType type) {
        return f.hub.getLog().getEntries().stream().filter(e -> e.getType() == type).count();
    }

    private static PeerAuditor.MemberChannel asProberAtB(TrustFixture t) {
        QueryService qs = new QueryService(t.b.hub, t.b.runtime);
        return (text, surface) -> qs.ask(new HubQuery(t.b.hub.getHubId(), t.a.admin.fingerprint(), text));
    }

    public static void testWithoutACredentialSchemeNothingCanBeSetUp() {
        TrustFixture t = new TrustFixture(false, null, 9, HubPolicy.Posture.COMMUNITY, null);
        Check.isNull(t.auditorB.getResponder().getIssuer().issue(t.a.admin.fingerprint(), t.b.hub.getRoster(),
                t.b.hubKey, t.today()), "no scheme, no credential");
        Check.isNull(t.setUp(), "no credential, no link");
        Check.equal(ProberEligibility.Result.NO_VALID_CREDENTIAL, t.auditorA.getLastRefusal(), "fails closed");
        Check.equal(0, t.auditorB.getWeb().getInbound().size(), "and the target recorded nothing");
    }

    public static void testAnHonestPeerIsUnlockedByItsInboundLinkOnly() {
        TrustFixture t = new TrustFixture();
        AuthLink link = t.setUp();
        Check.notNull(link, "set up");
        Check.equal(AuthLink.State.PENDING, link.getState(), "pending until it has measured something");
        Check.isNull(link.getProbingAdminUserId() == null ? null : t.auditorB.getWeb().getInbound().get(0)
                .getProbingAdminUserId(), "the target holds no user id");
        Check.equal(link.getLinkPseudonym(), t.auditorB.getWeb().getInbound().get(0).getLinkPseudonym(),
                "only the pseudonym");
        Check.equal(AuditSchedule.Mode.FULL, link.getMode(), "nine ordinary members: full mode");
        until(t, AuthLink.State.ACTIVE, 10);
        Check.equal(HubStanding.State.AUTHENTICATED, t.b.hub.getStanding().getState(),
                "the checked hub is unlocked by its inbound link");
        Check.isTrue(t.a.hub.getStanding().getState() != HubStanding.State.AUTHENTICATED,
                "checking someone else unlocks nothing (inbound only)");
        Check.isTrue(logged(t.b, HubLog.EventType.REPLAY_SAMPLE_OPENED) > 0, "openings are logged by count");
        Check.isTrue(t.auditorA.getLedger().getEntries().stream().allMatch(e -> e.getProbeTextHash() == null
                || e.getKind() != AuditRun.Kind.REPLAY), "the ledger holds no replayed text");
    }

    public static void testReplayCatchesATamperedCensorAndRevocationNeedsFreshEvidence() {
        TrustFixture t = new TrustFixture();
        t.setUp();
        until(t, AuthLink.State.ACTIVE, 10);
        t.bCensor.tamper(TamperableCensor.Mode.PASS_ALL);
        until(t, AuthLink.State.SUSPENDED, 10);
        java.time.Instant suspendedAt = t.link().getStateChangedAt();
        Check.equal(HubStanding.State.AUTHENTICATED, t.b.hub.getStanding().getState(),
                "suspended still counts: one bad window is not a verdict");
        Check.isTrue(t.auditorA.report(HubFixture.T0).stream()
                .anyMatch(a -> a.getKind() == AuditAnomaly.Kind.REPLAY_MISMATCH), "the admin is shown the mismatch");
        until(t, AuthLink.State.REVOKED, 10);
        Check.isTrue(!t.link().getStateChangedAt().isBefore(
                suspendedAt.plus(Duration.ofDays(t.auditorA.getSchedule().getSuspensionDays()))),
                "not before the suspension ran its course");
        Check.equal(HubStanding.State.PROVISIONAL, t.b.hub.getStanding().getState(),
                "its only inbound link revoked: provisional for 30 days, not silenced");
        Check.equal(AuthLink.State.REVOKED, t.auditorB.getWeb().getInbound().get(0).getState(),
                "the target learned the state, and only the state");
        t.clock.advance(Duration.ofDays(31));
        t.auditorB.refreshStanding(t.now());
        Check.equal(HubStanding.State.REVOKED, t.b.hub.getStanding().getState(), "then guest-only");
        Check.equal(AuthLink.State.REVOKED, t.auditorA.getWeb().assess(t.b.hubKey.fingerprint(), t.now()),
                "a revocation does not undo itself");
    }

    public static void testStatementsAndBondsAreSignedByTheRightHubs() {
        TrustFixture t = new TrustFixture();
        AuthLink link = t.setUp();
        until(t, AuthLink.State.ACTIVE, 10);
        AuthLink inbound = t.auditorB.getWeb().getInbound().get(0);
        LinkStatement forged = LinkStatement.issue(org.shalim.crypto.SoftwareSigner.generate(), link, t.now());
        Check.isFalse(inbound.applyStatement(forged, t.now()), "a statement not signed by the auditor is ignored");
        Check.equal(AuthLink.State.ACTIVE, inbound.getState(), "so nobody else can revoke a link");
        // A bond needs both directions; here B's link back to A is simulated.
        AuthLink back = new AuthLink(t.b.hubKey.fingerprint(), t.a.hubKey.fingerprint(), null,
                AuditSchedule.Mode.FULL, t.now());
        back.transition(AuthLink.State.ACTIVE, t.now(), null);
        AuthBond bond = AuthBond.formIfMutual(link, back, t.now());
        Check.notNull(bond, "mutual and counting: a bond forms");
        Check.isFalse(bond.isCurrent(t.now()), "but not until both have signed");
        bond.signAs(t.a.hubKey);
        bond.signAs(t.b.hubKey);
        Check.isTrue(bond.verify(bond.getKeyFingerprintA().equals(t.a.hubKey.fingerprint()) ? t.a.hubKey.publicKey()
                : t.b.hubKey.publicKey(), bond.getKeyFingerprintA().equals(t.a.hubKey.fingerprint())
                ? t.b.hubKey.publicKey() : t.a.hubKey.publicKey()), "co-signed");
        Check.isTrue(t.auditorA.getWeb().addBond(bond, t.now()), "recorded");
        t.clock.advance(AuthBond.TTL);
        Check.equal(0, t.auditorA.getWeb().refreshBonds(t.now()), "and lapses silently unless re-signed");
    }

    public static void testAnAppealKeepsTheEvidencePastRetention() {
        TrustFixture t = new TrustFixture();
        t.setUp();
        until(t, AuthLink.State.ACTIVE, 10);
        t.bCensor.tamper(TamperableCensor.Mode.PASS_ALL);
        until(t, AuthLink.State.REVOKED, 20);
        String rev = t.link().getRevocationId();
        Check.isTrue(t.auditorA.getLedger().evidenceFor(rev, null).size() > 0, "evidence pinned");
        Check.isTrue(t.auditorA.getWeb().openAppeal(t.b.hubKey.fingerprint()), "appealed");
        t.clock.advance(Duration.ofDays(40));
        t.auditorA.prune(t.now());
        Check.isTrue(t.auditorA.getLedger().evidenceFor(rev, null).size() > 0, "kept while the appeal is open");
        Check.notNull(t.link(), "and so is the link");
        t.auditorA.getWeb().closeAppeal(t.b.hubKey.fingerprint(), false, t.now());
        t.auditorA.prune(t.now());
        Check.equal(0, t.auditorA.getLedger().evidenceFor(rev, null).size(), "released when it closes");
        Check.isNull(t.link(), "and the revoked link is dropped with it");
    }

    public static void testMeetingRequestsAreReplayedAndCannotBeWithheld() {
        TrustFixture t = new TrustFixture();
        t.setUp();
        for (int i = 0; i < 32; i++) {
            t.screenAtB("blockme meet for a sale " + i, CensorEngine.Surface.MEETING_REQUEST);
        }
        List<AuditRun> runs = t.day(0);
        Check.isTrue(runs.get(0).getReplayRealScored() > 0, "meeting requests were read and replayed");
        Check.isFalse(runs.get(0).has(AuditAnomaly.Kind.OPENING_WITHHELD), "nothing withheld");
        t.b.admin().changePolicy(t.b.admin.fingerprint(), p -> p.setReplayMeetingRequests(false));
        for (int i = 0; i < 32; i++) {
            t.screenAtB("blockme meet for a sale " + i, CensorEngine.Surface.MEETING_REQUEST);
        }
        AuditRun r = t.day(0).get(0);
        Check.isTrue(r.getAnomalies().stream().anyMatch(a -> a.getKind() == AuditAnomaly.Kind.OPENING_WITHHELD
                && a.isConclusive()), "switching replay off is withholding, confirmed on retry");
        Check.equal(AuditRun.Verdict.FAILED, r.verdict(), "and fails the run: no posture is exempt");
    }

    public static void testTheTargetOpensOnlyForCommittedNoncesAndWithinItsCap() {
        TrustFixture t = new TrustFixture();
        AuthLink link = t.setUp();
        for (int i = 0; i < 64; i++) {
            t.screenAtB("lathe " + i, CensorEngine.Surface.HUB_QUERY);
        }
        t.clock.advance(Duration.ofDays(1));
        LocalDate d = t.today().minusDays(1);
        AuditResponder b = t.auditorB.getResponder();
        Check.notNull(b.head(d, t.now()), "yesterday has a head");
        Check.isNull(b.open(t.a.hubKey.fingerprint(), d, new byte[32], 5, t.now()), "a made-up nonce opens nothing");
        byte[] nonce = t.auditorA.getReplay().revealNonce(link, d);
        Check.equal(t.auditorB.getSchedule().getMaxReplayDrawPerDay(),
                b.open(t.a.hubKey.fingerprint(), d, nonce, 64, t.now()).size(), "never more than the daily cap");
        Check.isNull(b.open("someone-else", d, nonce, 5, t.now()), "and nothing for a hub with no link");
        Check.isNull(b.head(t.today(), t.now()), "today is not closed yet");
    }

    public static void testEquivocationAndUnloggedReceiptsAreConclusive() {
        TrustFixture t = new TrustFixture();
        AuthLink link = t.setUp();
        t.screenAtB("lathe", CensorEngine.Surface.HUB_QUERY);
        CensorDecisionLog.Receipt receipt = t.b.runtime.commitScreening("seed swap",
                t.b.runtime.getCensor().assess("seed swap", CensorEngine.Surface.HUB_QUERY),
                CensorEngine.Surface.HUB_QUERY, "answered", t.now());
        t.clock.advance(Duration.ofDays(1));
        LocalDate d = t.today().minusDays(1);
        CensorDecisionLog.SignedTreeHead real = t.auditorB.getResponder().head(d, t.now());
        ReplayAuditor ra = t.auditorA.getReplay();
        Check.isTrue(ra.acceptHead(real, t.b.hubKey.publicKey()), "head accepted");
        Check.isNull(ra.checkReceipt(t.b.hubKey.fingerprint(), t.b.hubKey.publicKey(), receipt,
                t.auditorB.getResponder().proveInclusion(d, receipt.getLeafIndex()), t.now()),
                "a receipt in the tree we were shown is fine");
        AuditAnomaly unlogged = ra.checkReceipt(t.b.hubKey.fingerprint(), t.b.hubKey.publicKey(), receipt,
                t.auditorB.getResponder().proveInclusion(d, 0), t.now());
        Check.equal(AuditAnomaly.Kind.UNLOGGED_DECISION, unlogged.getKind(), "a receipt not in it is unlogged");
        Check.isTrue(unlogged.isConclusive(), "and conclusive, being signed by the hub");
        // A second, different record for the same day, signed by B.
        CensorDecisionLog fork = new CensorDecisionLog(t.b.hubKey.fingerprint());
        fork.append("something else", t.b.runtime.getCensor().assess("x", CensorEngine.Surface.HUB_QUERY),
                CensorEngine.Surface.HUB_QUERY, "answered", t.b.hubKey, t.b.atRestKey, t.now().minus(Duration.ofDays(1)));
        CensorDecisionLog.SignedTreeHead other = fork.close(d, t.b.hubKey, t.now());
        Check.isTrue(ra.acceptHead(other, t.b.hubKey.publicKey()), "signed, so accepted as evidence");
        byte[] nonce = ra.revealNonce(link, d);
        AuditRun run = ra.replay(link, real, t.auditorB.getResponder().open(t.a.hubKey.fingerprint(), d, nonce, 3,
                t.now()), nonce, 3, t.now());
        Check.equal(AuditRun.Verdict.FAILED, run.verdict(), "two records for one day fail the run");
    }

    public static void testAPinMismatchIsVoidNotAFinding() {
        org.shalim.ml.stub.FixedCensor otherRelease = new org.shalim.ml.stub.FixedCensor(java.util.Map.of());
        TrustFixture t = new TrustFixture(true, otherRelease, 9, HubPolicy.Posture.COMMUNITY, null);
        t.setUp();
        for (int i = 0; i < 6; i++) {
            List<AuditRun> runs = t.day(24);
            Check.isTrue(runs.isEmpty() || runs.get(0).verdict() == AuditRun.Verdict.VOID, "different releases: void");
        }
        Check.equal(AuthLink.State.PENDING, t.link().getState(), "the link neither passes nor fails");
        Check.isTrue(t.auditorA.report(HubFixture.T0).get(0).concernsAuditor(),
                "and the admin is told first that the releases differ");
    }

    public static void testDoubleSpendingUnmasksTheProberAndNoOneElse() {
        TrustFixture t = new TrustFixture();
        t.setUp();
        t.clock.advance(Duration.ofDays(1));
        t.refreshCredential();
        AuditResponder b = t.auditorB.getResponder();
        MemberCredential c = b.getIssuer().issue(t.a.admin.fingerprint(), t.b.hub.getRoster(), t.b.hubKey, t.today())
                .holding(t.proberSecret);
        EligibilityProof first = c.presentEligibility(t.scheme, t.a.hubKey.fingerprint(), t.today(), 14, b.newChallenge());
        EligibilityProof second = c.presentEligibility(t.scheme, t.a.hubKey.fingerprint(), t.today(), 14,
                b.newChallenge());
        Check.equal(ProberEligibility.Result.ELIGIBLE, b.presentDaily(t.a.hubKey.fingerprint(), first, t.now()), "once");
        Check.equal(ProberEligibility.Result.ELIGIBLE, b.presentDaily(t.a.hubKey.fingerprint(), first, t.now()),
                "a retransmission is harmless");
        Check.equal(ProberEligibility.Result.NULLIFIER_DOUBLE_SPENT,
                b.presentDaily(t.a.hubKey.fingerprint(), second, t.now()), "twice with a new challenge is not");
        String mid = t.b.hub.getRoster().membershipOf(t.a.admin.fingerprint()).get().getMembershipId();
        Check.isTrue(t.b.hub.getLog().getEntries().stream().anyMatch(e -> e.getType()
                == HubLog.EventType.NULLIFIER_DOUBLE_SPENT && mid.equals(e.getSubjectId())),
                "traced to exactly that membership");
    }

    public static void testPromotionToAdminThereEndsTheLinkTheSameDay() {
        TrustFixture t = new TrustFixture();
        t.setUp();
        until(t, AuthLink.State.ACTIVE, 10);
        t.b.admin().assignRole(t.b.admin.fingerprint(), t.a.admin.fingerprint(), Role.ADMIN);
        t.day(4);
        Check.equal(AuthLink.State.INELIGIBLE, t.link().getState(), "no credential is issued to admins");
        Check.isFalse(t.link().counts(t.now()), "and it stops counting at once");
    }

    public static void testSharedAdminsAndSmallHubs() {
        TrustFixture shared = new TrustFixture();
        shared.a.admin().admit(shared.a.admin.fingerprint(), shared.b.admin.fingerprint(), Role.MEMBER, null, null,
                null, false);
        shared.a.admin().assignRole(shared.a.admin.fingerprint(), shared.b.admin.fingerprint(), Role.ADMIN);
        Check.isNull(shared.setUp(), "hubs sharing an admin cannot check each other");
        Check.equal(ProberEligibility.Result.SHARED_ADMIN, shared.auditorA.getLastRefusal(), "and are told why");

        TrustFixture small = new TrustFixture(true, null, 3, HubPolicy.Posture.COMMUNITY, null);
        AuthLink link = small.setUp();
        Check.notNull(link, "a small hub can still be checked");
        Check.equal(AuditSchedule.Mode.REPLAY_ONLY, link.getMode(), "from its records only");
        Check.isNull(small.auditorA.sendSynthetic(link, small.today(), 1, asProberAtB(small), small.now()),
                "and nothing is ever sent under the prober's name");

        TrustFixture fresh = new TrustFixture();
        fresh.b.admin().remove(fresh.b.admin.fingerprint(), fresh.a.admin.fingerprint());
        fresh.b.admin().admit(fresh.b.admin.fingerprint(), fresh.a.admin.fingerprint(), Role.MEMBER, null, null, null,
                false);
        fresh.auditorB.getResponder().getIssuer().enrol(fresh.a.admin.fingerprint(),
                fresh.b.hub.getRoster().membershipOf(fresh.a.admin.fingerprint()).get().getMembershipId(),
                EpochNullifier.commitment(fresh.proberSecret), List.of(new byte[] {1}), new byte[] {2}, fresh.now());
        fresh.refreshCredential();
        Check.isNull(fresh.setUp(), "a member of a few days cannot carry a link");
        Check.equal(ProberEligibility.Result.MEMBERSHIP_TOO_RECENT, fresh.auditorA.getLastRefusal(),
                "worked out on the device, so the target distinguishes nothing");
    }

    public static void testSyntheticProbesCatchOverBlockingOfProtectedSpeech() {
        TrustFixture t = new TrustFixture();
        AuthLink link = t.setUp();
        until(t, AuthLink.State.ACTIVE, 10);
        PeerAuditor.MemberChannel channel = asProberAtB(t);
        AuditRun clean = t.auditorA.sendSynthetic(link, t.today(), 3, channel, t.now());
        Check.notNull(clean, "sent");
        Check.isTrue(clean.getSample().get(0).sendableToPeer(), "PASS-side only");
        Check.isNull(clean.getSample().get(0).getText(), "text forgotten once scored");
        t.bCensor.tamper(TamperableCensor.Mode.BLOCK_WORDS, "overdose", "border");
        int over = 0;
        for (long seed = 10; seed < 60 && over < 4; seed++) {
            t.clock.advance(Duration.ofHours(3)); // Poisson-spaced, and inside the ordinary rate limit
            AuditRun r = t.auditorA.sendSynthetic(link, t.today(), seed, channel, t.now());
            if (r != null && r.getScores().stream().anyMatch(DifferenceScore::isPeerOverBlock)) {
                over++;
            }
        }
        Check.isTrue(over >= 3, "protected speech refused");
        Check.equal(AuthLink.State.SUSPENDED, t.link().getState(), "significant over-blocking suspends");
    }

    public static void testOrganicReceiptsCatchAnUnloggedScreening() {
        TrustFixture t = new TrustFixture();
        AuthLink link = t.setUp();
        until(t, AuthLink.State.ACTIVE, 10);
        OrganicProbe probe = OrganicProbe.shadow("who can fix a lathe", CensorEngine.Surface.HUB_QUERY, t.a.censor,
                t.b.hubKey.fingerprint(), t.now());
        QueryResult answer = asProberAtB(t).ask("who can fix a lathe", CensorEngine.Surface.HUB_QUERY);
        probe.observe(answer, t.now());
        Check.notNull(probe.getReceipt(), "a receipt came back");
        t.day(70);
        LocalDate d = probe.getReceipt().getDay();
        CensorDecisionLog.InclusionProof proof = t.auditorB.getResponder().proveInclusion(d,
                probe.getReceipt().getLeafIndex());
        Check.isTrue(probe.checkInclusion(proof, t.auditorB.getResponder().head(d, t.now())), "in the tree");
        AuditRun ok = t.auditorA.acceptOrganic(probe, proof, t.now());
        Check.isTrue(ok.getAnomalies().isEmpty(), "an honest hub logs what it screens");
        Check.isNull(probe.getTextHash(), "the device keeps nothing but the score");

        OrganicProbe second = OrganicProbe.shadow("who teaches sewing", CensorEngine.Surface.HUB_QUERY, t.a.censor,
                t.b.hubKey.fingerprint(), t.now());
        second.observe(asProberAtB(t).ask("who teaches sewing", CensorEngine.Surface.HUB_QUERY), t.now());
        t.day(70);
        // The hub shows its member a proof that does not lead to the root it gave auditors.
        CensorDecisionLog.InclusionProof wrong = new CensorDecisionLog.InclusionProof(
                second.getReceipt().getLeafIndex(), proof.getTreeSize(), proof.getPath());
        AuditRun bad = t.auditorA.acceptOrganic(second, wrong, t.now());
        Check.equal(AuditRun.Verdict.FAILED, bad.verdict(), "an unlogged screening is conclusive");
        Check.equal(AuthLink.State.SUSPENDED, t.link().getState(), "and suspends the link");
    }

    public static void testABlackoutIsDormancyNotRevocation() {
        TrustFixture t = new TrustFixture();
        t.setUp();
        until(t, AuthLink.State.ACTIVE, 10);
        for (int i = 0; i < 9; i++) {
            t.clock.advance(Duration.ofDays(1));
            t.auditorA.runDaily(t.today(), t.now(), java.util.Map.of(), u -> t.wallet);
        }
        Check.equal(AuthLink.State.DORMANT, t.link().getState(), "nothing heard: dormant");
        t.auditorB.refreshStanding(t.now());
        Check.equal(HubStanding.State.AUTHENTICATED, t.b.hub.getStanding().getState(),
                "statements lapsed, but a checked hub fails open in a blackout");
        until(t, AuthLink.State.ACTIVE, 6);
    }

    public static void testHighRiskHubsAreReplayedWeeklyAndNeverProbed() {
        TrustFixture t = new TrustFixture(true, null, 13, HubPolicy.Posture.HIGH_RISK,
                AuditSchedule.defaultsFor(HubPolicy.Posture.HIGH_RISK).withWindow(6, 3, 3, 21));
        AuthLink link = t.setUp();
        Check.notNull(link, "set up");
        int replayDays = 0;
        for (int i = 0; i < 14; i++) {
            replayDays += t.day(24).isEmpty() ? 0 : 1;
        }
        Check.isTrue(replayDays >= 1 && replayDays <= 3, "openings come in weekly batches, not daily");
        Check.equal(AuthLink.State.ACTIVE, t.link().getState(), "and still check the hub");
        Check.isNull(t.auditorA.sendSynthetic(link, t.today(), 1, asProberAtB(t), t.now()), "no synthetic traffic");
    }
}
