package org.shalim.trust;

import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import java.time.ZoneOffset;
import org.shalim.hub.CensorDecisionLog;
import org.shalim.hub.Hub;
import org.shalim.hub.HubRuntime;

/**
 * Runs authentication of peers. Coordinates the three evidence streams —
 * replay of the peer's committed censor decisions, organic probes from the
 * prober's own questions, and Poisson-scheduled synthetic PASS-side probes —
 * and hands the results to {@link WebOfTrust}.
 *
 * <h2>What changed on 30 September 2026</h2>
 *
 * <p>Previously the peer knew which of its members was the prober, because
 * it had to: the prober sent a supply request every day, and without being
 * told, the peer would have restricted them for it. That knowledge let a
 * dishonest hub answer the prober correctly and everyone else however it
 * liked. Now:
 * <ul>
 *   <li>No supply request is ever sent to a peer. Under-blocking is tested by
 *       {@link ReplayAuditor} on the peer's committed real traffic.</li>
 *   <li>So the peer no longer needs to know who the prober is, and is not
 *       told. The prober proves eligibility with an anonymous
 *       {@link MemberCredential}; the target records only pseudonyms.</li>
 *   <li>{@code isInboundProber} is deleted. Nothing the prober sends needs a
 *       moderation exemption, so the hook a dishonest hub would use for
 *       special-casing no longer exists.</li>
 *   <li>Probes that remain are either real questions ({@link OrganicProbe}) or
 *       PASS-side synthetic questions at a Poisson rate scaled to the peer's
 *       traffic, and both stop entirely for quiet or tiny peers, which fall
 *       back to replay only.</li>
 * </ul>
 *
 * <p>Every probe still travels as an ordinary {@link org.shalim.query.HubQuery}
 * through the prober's ordinary membership and the peer's ordinary query path
 * and rate limits. There is still no audit endpoint for questions. Replay
 * uses sync, which exists anyway.
 */
public final class PeerAuditor {

    /**
     * The prober's ordinary membership in a peer, on their own device: how a
     * synthetic probe is asked. Ordinary query path, ordinary rate limit,
     * ordinary moderation if held. Matches that come back are never read.
     */
    @FunctionalInterface
    public interface MemberChannel {
        org.shalim.query.QueryResult ask(String text, org.shalim.ml.CensorEngine.Surface surface);
    }

    /** What a manual disclosure sends: kinds, cited leaves or regenerated texts, both sides' decisions. */
    public record Disclosure(String runId, String peerKeyFingerprint, List<AuditAnomaly.Kind> kinds,
                             List<String> citedProbeIds, List<String> regeneratedTexts) {
    }

    private final HubRuntime runtime;
    private final AuditSchedule schedule;
    private final ProbeCorpus corpus;
    private final ProbeLedger ledger;
    private final WebOfTrust web;
    private final ReplayAuditor replay;
    private final org.shalim.ml.ProbeEngine prober;
    private final org.shalim.crypto.EncryptionKeyPair encryptionKeys;
    private final AuditResponder responder;
    private final org.shalim.hub.ProvisionalStatus provisional;

    /** The last reason a set-up was refused, for the admin who tried. */
    private ProberEligibility.Result lastRefusal;

    /**
     * @param issuer this hub's credential issuer, for the target side; its
     *               scheme may be null, in which case nobody here can be
     *               issued a credential and no link into this hub can be set
     *               up (fail closed)
     */
    public PeerAuditor(HubRuntime runtime, ProbeCorpus corpus, AuditSchedule schedule,
                       org.shalim.ml.ProbeEngine prober, org.shalim.crypto.EncryptionKeyPair encryptionKeys,
                       MemberCredentialIssuer issuer) {
        this.runtime = runtime;
        this.schedule = schedule == null ? AuditSchedule.defaultsFor(runtime.getHub().getPolicy().getPosture())
                : schedule;
        this.corpus = corpus;
        this.prober = prober;
        this.encryptionKeys = encryptionKeys;
        String own = runtime.getHubKey().fingerprint();
        this.ledger = new ProbeLedger(own);
        this.provisional = org.shalim.hub.ProvisionalStatus.forHub(runtime.getHub());
        this.web = new WebOfTrust(own, ledger).configure(this.schedule, runtime.getHub().getPolicy())
                .withProvisional(provisional)
                .withEvents((type, peer, detail, now) -> runtime.log(type, null, peer, detail, now));
        this.replay = new ReplayAuditor(own, runtime.getCensor(), ledger, encryptionKeys);
        this.responder = new AuditResponder(runtime, issuer, new NullifierRegistry(own), this.schedule, web,
                () -> refreshStanding(runtime.now()));
    }

    // --- setting up -------------------------------------------------------

    /** What the admin is shown, and must agree to, before a link is set up. */
    public static String consentText(String peerName, String thisHubName, AuditSchedule.Mode mode) {
        if (mode == AuditSchedule.Mode.REPLAY_ONLY) {
            return peerName + " is small, so it will be checked from its records only."
                    + " Nothing will be sent under your name.";
        }
        return peerName + " will be checked from its records every day. Some of your own questions there will"
                + " also be checked on your phone, and now and then Shalim will ask " + peerName + " an ordinary"
                + " question on your behalf. " + peerName + " will know that some member is checking it for "
                + thisHubName + ", but not that it is you. No test question will ever ask for anything harmful.";
    }

    /**
     * Sets up authentication of one peer, through this admin's ordinary
     * membership there. The link starts PENDING and unlocks the
     * <em>peer</em> once it passes its first window (inbound only). Returns
     * null if refused; {@link #getLastRefusal()} says why.
     */
    public AuthLink setUpAuthentication(LinkPeer peer, String adminUserId, ProberCredentials device,
                                        boolean consented, Instant now) {
        lastRefusal = null;
        Hub hub = runtime.getHub();
        org.shalim.identity.Membership m = hub.getRoster().membershipOf(adminUserId).orElse(null);
        if (!consented || m == null
                || !m.can(org.shalim.identity.Permission.MANAGE_AUTHENTICATION, hub.getStanding())
                || ProberEligibility.checkOutbound(adminUserId, hub) != ProberEligibility.Result.ELIGIBLE) {
            lastRefusal = ProberEligibility.Result.NOT_ADMIN_HERE;
            return null;
        }
        String own = runtime.getHubKey().fingerprint();
        // 1. No shared admins, by PSI-CA. Hub-to-hub, never through the membership.
        byte[] exp = AdminOverlapCheck.newExponent();
        List<String> admins = hub.getRoster().getMemberships().stream()
                .filter(x -> x.getRole() == org.shalim.identity.Role.ADMIN)
                .map(org.shalim.identity.Membership::getUserId).toList();
        List<byte[]> theirs = peer.overlapRound1(own, AdminOverlapCheck.blindOwnAdmins(admins, exp));
        peer.overlapRound2(own, AdminOverlapCheck.doubleBlind(theirs, exp));
        // 2. The admin's device presents an anonymous credential for the peer.
        LocalDate today = LocalDate.ofInstant(now, ZoneOffset.UTC);
        EligibilityProof proof = device == null ? null : device.present(peer.keyFingerprint(), own, today,
                schedule.getMinProberMembershipDays(), peer.newChallenge());
        if (proof == null) {
            lastRefusal = device == null ? ProberEligibility.Result.NO_VALID_CREDENTIAL
                    : device.whyNot(peer.keyFingerprint(), today, schedule.getMinProberMembershipDays());
            return null;
        }
        // 3. The link, with a fresh nonce chain whose anchor goes to the peer.
        AuthLink link = web.setUp(peer.keyFingerprint(), peer.publicKey(), adminUserId, proof.getLinkPseudonym(),
                AuditSchedule.Mode.FULL, ProberEligibility.Result.ELIGIBLE, now);
        ProberEligibility.Result r = peer.requestLink(new LinkPeer.LinkRequest(own, runtime.getHubKey().publicKey(),
                encryptionKeys.publicKey(), proof, link.getNonceCommitment(), link.nonceChainStart()), now);
        if (!ProberEligibility.permitsLink(r)) {
            web.ineligible(link, r, now);
            lastRefusal = r;
            return null;
        }
        link.setEligibility(r, now);
        link.setMode(schedule.modeFor(Integer.MAX_VALUE, r));
        return link;
    }

    /**
     * Asks a peer this hub authenticates to authenticate it back: the fix for
     * a hub with no inbound link. Carries a single-use membership invitation,
     * because the peer's admin can only check this hub as an ordinary member
     * of it.
     */
    public ReciprocityInvite inviteReciprocity(AuthLink outbound, String adminUserId, String membershipInvitationId,
                                               Instant now) {
        if (outbound == null || (outbound.getState() != AuthLink.State.PENDING
                && outbound.getState() != AuthLink.State.ACTIVE)) {
            return null;
        }
        ReciprocityInvite invite = new ReciprocityInvite(runtime.getHubKey().fingerprint(),
                outbound.getSubjectKeyFingerprint(), adminUserId, membershipInvitationId, now);
        runtime.log(org.shalim.hub.HubLog.EventType.RECIPROCITY_INVITE_SENT, adminUserId,
                outbound.getSubjectKeyFingerprint(), null, now);
        return invite;
    }

    // --- the daily run -----------------------------------------------------

    /**
     * One day's authentication of every outbound peer: re-present, replay,
     * statement. Organic scores arrive as the prober's device forwards them
     * ({@link #acceptOrganic}); synthetic probes run on their own Poisson
     * schedule ({@link #sendSynthetic}).
     *
     * @param peers  reachable peers by key fingerprint; an absent peer is simply not heard from today
     * @param device the probing admin's device, for re-presentation
     */
    public List<AuditRun> runDaily(LocalDate day, Instant now, java.util.Map<String, LinkPeer> peers,
                                   java.util.function.Function<String, ProberCredentials> device) {
        List<AuditRun> out = new java.util.ArrayList<>();
        if (!schedule.isEnabled()) {
            return out;
        }
        String own = runtime.getHubKey().fingerprint();
        for (AuthLink link : web.getOutbound()) {
            if (link.isRevoked() || link.getState() == AuthLink.State.INELIGIBLE) {
                continue;
            }
            LinkPeer peer = peers.get(link.getSubjectKeyFingerprint());
            if (peer == null) {
                web.assess(link.getSubjectKeyFingerprint(), now); // lets dormancy advance
                continue;
            }
            // 1. Re-proved daily. Promotion to admin there ends the link today.
            ProberCredentials creds = device == null ? null : device.apply(link.getProbingAdminUserId());
            EligibilityProof proof = creds == null ? null : creds.present(peer.keyFingerprint(), own, day,
                    schedule.getMinProberMembershipDays(), peer.newChallenge());
            ProberEligibility.Result r = proof == null ? ProberEligibility.Result.NO_VALID_CREDENTIAL
                    : peer.presentDaily(own, proof, now);
            if (!ProberEligibility.permitsLink(r)) {
                web.ineligible(link, r, now);
                peer.deliverStatement(LinkStatement.issue(runtime.getHubKey(), link, now), now);
                continue;
            }
            link.setEligibility(r, now);
            // 2. Replay: yesterday, or the past week in one batch for HIGH_RISK.
            List<LocalDate> days = new java.util.ArrayList<>();
            if (!schedule.isReplayBatchedWeekly()) {
                days.add(day.minusDays(1));
            } else if (link.dayInFortnight(day) % 7 == 6) {
                for (int i = 7; i >= 1; i--) {
                    days.add(day.minusDays(i));
                }
            }
            for (LocalDate d : days) {
                AuditRun run = replayOne(link, peer, d, now);
                if (run != null) {
                    out.add(run);
                    CensorDecisionLog.SignedTreeHead h = replay.headFor(peer.keyFingerprint(), d);
                    if (h != null) {
                        link.setMode(schedule.modeFor(h.trafficBand(), link.getEligibility()));
                    }
                }
            }
            if (days.isEmpty()) {
                web.assess(link.getSubjectKeyFingerprint(), now);
            }
            // 3. Tell the peer where it stands.
            peer.deliverStatement(LinkStatement.issue(runtime.getHubKey(), link, now), now);
        }
        web.refreshBonds(now);
        return out;
    }

    private AuditRun replayOne(AuthLink link, LinkPeer peer, LocalDate d, Instant now) {
        CensorDecisionLog.SignedTreeHead head = peer.head(d, now);
        if (head == null || !replay.acceptHead(head, link.getSubjectPublicKey())) {
            return null;
        }
        boolean small = link.getEligibility() == ProberEligibility.Result.ANONYMITY_SET_TOO_SMALL;
        int size = schedule.replayDraw(link.dayInFortnight(d), link.realScoredThisFortnight(d), link.realFraction(),
                small);
        if (size == 0) {
            return null;
        }
        byte[] nonce = replay.revealNonce(link, d);
        List<CensorDecisionLog.Opening> openings = peer.open(runtime.getHubKey().fingerprint(), d, nonce, size, now);
        if (openings == null) {
            return null; // no answer is not a refusal
        }
        AuditRun run = replay.replay(link, head, openings, nonce, size, now);
        if (run.has(AuditAnomaly.Kind.OPENING_WITHHELD)) {
            // A flat battery mid-sync is not a refusal: ask again before it counts.
            List<CensorDecisionLog.Opening> again = peer.open(runtime.getHubKey().fingerprint(), d, nonce, size, now);
            if (again != null) {
                run = replay.replay(link, head, again, nonce, size, now);
                run.getAnomalies().stream().filter(a -> a.getKind() == AuditAnomaly.Kind.OPENING_WITHHELD)
                        .forEach(AuditAnomaly::confirmOnRetry);
            }
        }
        link.countOpened(d, run.getReplayRealScored() + run.getReplayUndetermined(), run.getReplayPads(),
                run.getReplayRealScored());
        web.record(run, now);
        return run;
    }

    /**
     * An organic probe forwarded by the prober's device: its score, and, if
     * the device's own inclusion check failed or was not possible, the
     * receipt and the peer's proof, checked here against the head this hub
     * was shown. The text was never here.
     */
    public AuditRun acceptOrganic(OrganicProbe probe, CensorDecisionLog.InclusionProof proof, Instant now) {
        AuthLink link = web.outboundTo(probe.getPeerKeyFingerprint());
        if (link == null || link.getMode() != AuditSchedule.Mode.FULL || link.isRevoked()) {
            probe.forget();
            return null;
        }
        AuditRun run = AuditRun.organic(probe.getPeerKeyFingerprint(), now);
        DifferenceScore score = probe.toScore(prober);
        run.addProbe(null, null, null, score);
        ledger.recordOrganic(score, now);
        if (probe.getReceipt() != null) {
            AuditAnomaly a = replay.checkReceipt(probe.getPeerKeyFingerprint(), link.getSubjectPublicKey(),
                    probe.getReceipt(), proof, now);
            if (a != null) {
                run.addAnomaly(a);
            }
        } else if (probe.isAnsweredWithoutReceipt()) {
            // Without the hub's signature this cannot be proved, so it is
            // shown to the admin and never acted on alone.
            run.addAnomaly(AuditAnomaly.of(AuditAnomaly.Kind.UNLOGGED_DECISION, AuditAnomaly.Attribution.UNDETERMINED,
                    null, null, "The hub answered a question without giving a receipt.", now));
        }
        if (score.isPeerOverBlock()) {
            run.addAnomaly(AuditAnomaly.statistical(AuditAnomaly.Kind.OVER_BLOCKING, AuditAnomaly.Attribution.PEER,
                    null, 1, schedule.getOverBlockBaseline(), 1.0, List.of(), "An ordinary question was refused"
                            + " that this hub's own screening would have let through.", now));
        }
        probe.forget();
        web.record(run, now);
        return run;
    }

    /**
     * Plans the next synthetic probe for one FULL-mode link. Called when the
     * previous one resolves, and on startup. Null when none is due.
     */
    public Instant scheduleSynthetic(AuthLink link, int peerTrafficBand, Instant now,
                                     java.util.random.RandomGenerator rng, AuditSchedule.ActiveHours hours) {
        if (schedule.modeFor(peerTrafficBand, link.getEligibility()) != AuditSchedule.Mode.FULL) {
            return null;
        }
        return schedule.nextSyntheticAt(now, schedule.syntheticRatePerDay(peerTrafficBand), rng, hours);
    }

    /**
     * Sends one synthetic probe when its time comes. PASS-side only. Run
     * against this hub's censor first, then asked of the peer under the
     * prober's ordinary membership.
     */
    public AuditRun sendSynthetic(AuthLink link, LocalDate day, long seed, MemberChannel channel, Instant now) {
        if (link == null || link.getMode() != AuditSchedule.Mode.FULL || schedule.getMaxSyntheticPerDay() <= 0
                || prober == null || corpus == null || channel == null) {
            return null;
        }
        TrustProbe probe = prober.generateSynthetic(corpus, day, seed);
        if (probe == null || !probe.sendableToPeer()) {
            return null; // never a supply request, whatever the generator returned
        }
        org.shalim.ml.CensorEngine censor = runtime.getCensor();
        String own = runtime.getHubKey().fingerprint();
        ProbeOutcome local = censor == null ? ProbeOutcome.failed(probe.getProbeId(), own, "no local censor")
                : ProbeOutcome.fromVerdict(probe.getProbeId(), own, censor.assess(probe.getText(), probe.getSurface()),
                        censor.isVerified());
        org.shalim.query.QueryResult answer = channel.ask(probe.getText(), probe.getSurface());
        ProbeOutcome peer = ProbeOutcome.fromQueryResult(probe.getProbeId(), link.getSubjectKeyFingerprint(), answer,
                now);
        DifferenceScore score = prober.score(probe, local, peer);
        AuditRun run = new AuditRun(link.getSubjectKeyFingerprint(), corpus, seed);
        run.addProbe(probe, local, peer, score);
        for (AuditAnomaly a : analyse(run, now)) {
            run.addAnomaly(a);
        }
        ledger.record(probe, peer, score);
        probe.forgetText();
        run.complete(now, null);
        web.record(run, now);
        return run;
    }

    /**
     * Per-run findings for synthetic runs: over-blocking against the peer,
     * and anything that points back at this hub, which is shown first.
     */
    public List<AuditAnomaly> analyse(AuditRun run, Instant now) {
        List<AuditAnomaly> out = new java.util.ArrayList<>();
        if (run.getKind() != AuditRun.Kind.SYNTHETIC) {
            return out;
        }
        for (DifferenceScore d : run.getScores()) {
            if (!d.isScoreable()) {
                continue;
            }
            if (d.isPeerOverBlock()) {
                out.add(AuditAnomaly.statistical(AuditAnomaly.Kind.OVER_BLOCKING, AuditAnomaly.Attribution.PEER, null,
                        1, schedule.getOverBlockBaseline(), schedule.getOverBlockBaseline(), List.of(d.getProbeId()),
                        "The other hub refused a question it should have let through.", now));
            } else if (d.attribution() == AuditAnomaly.Attribution.LOCAL) {
                out.add(AuditAnomaly.statistical(AuditAnomaly.Kind.OVER_BLOCKING, AuditAnomaly.Attribution.LOCAL, null,
                        1, 0, 1.0, List.of(d.getProbeId()),
                        "This hub's own screening got a test question wrong that the other hub got right.", now));
            }
        }
        for (ProbeOutcome o : run.getPeerOutcomes()) {
            String localPin = runtime.getCensor() == null ? null : runtime.getCensor().pin().getArtefactHash();
            if (o.getModelPinHash() != null && localPin != null
                    && !org.shalim.crypto.Bytes.equalHex(o.getModelPinHash(), localPin)) {
                out.add(AuditAnomaly.of(AuditAnomaly.Kind.PIN_DIVERGENCE, AuditAnomaly.Attribution.UNDETERMINED, null,
                        null, "The other hub reports a different censor release.", now));
            }
        }
        return out;
    }

    // --- disclosure -------------------------------------------------------

    /**
     * Tells a peer what was found. Manual, per finding, and off every
     * automatic path. Replay findings cite the peer's own leaves; synthetic
     * findings cite regenerated texts, which are then spent for this peer.
     * Never anything from an organic probe: that is the prober's own question.
     */
    public Disclosure disclose(AuditRun run, List<AuditAnomaly> selected, String byAdminUserId) {
        Hub hub = runtime.getHub();
        org.shalim.identity.Membership m = hub.getRoster().membershipOf(byAdminUserId).orElse(null);
        if (m == null || !m.can(org.shalim.identity.Permission.MANAGE_AUTHENTICATION, hub.getStanding())
                || run == null || run.getKind() == AuditRun.Kind.ORGANIC) {
            return null;
        }
        List<AuditAnomaly> chosen = selected == null ? List.of()
                : selected.stream().filter(a -> run.getAnomalies().contains(a)).toList();
        List<String> cited = new java.util.ArrayList<>();
        chosen.forEach(a -> a.getProbeIds().forEach(cited::add));
        List<String> texts = new java.util.ArrayList<>();
        if (run.getKind() == AuditRun.Kind.SYNTHETIC && prober != null) {
            for (TrustProbe p : run.getSample()) {
                if (cited.contains(p.getProbeId())) {
                    String t = prober.regenerate(p);
                    if (t != null) {
                        texts.add(t);
                    }
                }
            }
        }
        run.markDisclosed();
        return new Disclosure(run.getRunId(), run.getPeerKeyFingerprint(),
                chosen.stream().map(AuditAnomaly::getKind).toList(), cited, texts);
    }

    /** Findings the admin must be shown, own-hub faults first. */
    public List<AuditAnomaly> report(Instant since) {
        return web.findings(since);
    }

    // --- standing ---------------------------------------------------------

    /** Records a hub seen nearby, for the provisional clock. */
    public boolean noteNearbyHub(org.shalim.hub.ProvisionalStatus.NearbyHub seen) {
        return provisional.observe(seen);
    }

    /** Recomputes and installs this hub's standing from its inbound links and clocks. */
    public org.shalim.hub.HubStanding refreshStanding(Instant now) {
        org.shalim.hub.HubStanding s = web.standing(runtime.getHub().getPolicy(), now);
        new org.shalim.hub.HubAdministration(runtime.getHub(), runtime).updateStanding(s);
        return s;
    }

    /** Daily retention for everything authentication keeps. */
    public int prune(Instant now) {
        int n = web.prune(runtime.getHub().getPolicy(), now);
        return n + replay.pruneHeads(LocalDate.ofInstant(now, ZoneOffset.UTC)
                .minusDays(runtime.getHub().getPolicy().getMeetingRequestRetentionDays()));
    }

    /** Duress path. */
    public void wipe() {
        web.wipe();
        replay.wipe();
        responder.getRegistry().wipe();
    }

    // --- accessors --------------------------------------------------------

    public ProberEligibility.Result getLastRefusal() {
        return lastRefusal;
    }

    public AuditResponder getResponder() {
        return responder;
    }

    public org.shalim.hub.ProvisionalStatus getProvisional() {
        return provisional;
    }

    public AuditSchedule getSchedule() {
        return schedule;
    }

    public ProbeCorpus getCorpus() {
        return corpus;
    }

    public WebOfTrust getWeb() {
        return web;
    }

    public ProbeLedger getLedger() {
        return ledger;
    }

    public ReplayAuditor getReplay() {
        return replay;
    }

    public org.shalim.ml.ProbeEngine getProber() {
        return prober;
    }
}
