package org.shalim.trust;

import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import org.shalim.hub.Hub;
import org.shalim.transport.PeerEndpoint;

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
public class PeerAuditor {

    private Hub localHub;

    private AuditSchedule schedule;

    private ProbeCorpus corpus;

    private WebOfTrust web;

    private ProbeLedger ledger;

    private ReplayAuditor replay;

    private org.shalim.ml.ProbeEngine prober;

    public PeerAuditor() {
        // TODO: pseudo-code
    }

    public PeerAuditor(Hub localHub, ProbeCorpus corpus, AuditSchedule schedule,
                       WebOfTrust web, ReplayAuditor replay, org.shalim.ml.ProbeEngine prober) {
        // TODO: pseudo-code
    }

    // --- setting up -------------------------------------------------------

    /**
     * Peers this hub could authenticate: hubs where one of its admins holds a
     * current {@link MemberCredential}. Derived from credentials on this
     * device, never from anything a peer advertises.
     */
    public List<PeerEndpoint> authenticablePeers(String adminUserId, Instant now) {
        // TODO: pseudo-code
        return null;
    }

    /**
     * Sets up authentication of one peer. This is the step that ends a new
     * hub's guest-only period, once the link has passed its first window
     * (see {@link org.shalim.hub.HubStanding} for which direction counts).
     */
    public AuthLink setUpAuthentication(PeerEndpoint peer, String adminUserId, Instant now) {
        // PSEUDO-CODE
        // 1. IF adminUserId lacks MANAGE_AUTHENTICATION here -> RETURN null
        // 2. result = ProberEligibility.checkOutbound(adminUserId, localHub, peer, now)
        //    IF NOT ProberEligibility.permitsLink(result)
        //       -> show ProberEligibility.explain(result); RETURN null
        //    mode = result == ANONYMITY_SET_TOO_SMALL ? REPLAY_ONLY : FULL
        // 3. SHOW THE COST and require explicit consent:
        //    FULL:
        //    "<peer> will be checked from its records every day. Some of your
        //     own questions there will also be checked on your phone, and now
        //     and then Shalim will ask <peer> an ordinary question on your
        //     behalf. <peer> will know that some member is checking it for
        //     <this hub>, but not that it is you. No test question will ever
        //     ask for anything harmful."
        //    REPLAY_ONLY:
        //    "<peer> is small, so it will be checked from its records only.
        //     Nothing will be sent under your name."
        // 4. nonceSecret = fresh random; send commit H(nonceSecret) to peer,
        //    hub-to-hub, so the peer can later check each day's nonce
        // 5. link = web.setUp(peer.keyFingerprint, adminUserId, mode, nonceSecret, now)
        //    // PENDING. adminUserId is recorded HERE only; the peer never has it.
        // 6. RETURN link
        return null;
    }

    /**
     * Asks a peer this hub authenticates to authenticate it back. The fix for
     * a hub that authenticates others but has no inbound link, and so has no
     * bonds and is invisible to search.
     */
    public ReciprocityInvite inviteReciprocity(AuthLink outbound, String adminUserId, Instant now) {
        // PSEUDO-CODE
        // IF outbound.state NOT IN (PENDING, ACTIVE) -> RETURN null
        // invite = new ReciprocityInvite(own key, outbound.subject, adminUserId, now)
        // invite.membershipInvitationId = single-use MEMBER invitation to this hub
        //    // The peer's admin must join this hub, and then wait
        //    // minProberMembershipDays, before they can carry a link back.
        // send hub-to-hub, not through adminUserId's membership there
        //    // Sending through the membership would tie the invite, and so the
        //    // outbound link, to a particular member of the peer.
        // log RECIPROCITY_INVITE_SENT
        // RETURN invite
        return null;
    }

    /**
     * The target side of setting up a link: some ordinary member here,
     * identity unknown, presents an {@link EligibilityProof} on behalf of
     * another hub. This hub's admins accept or decline the <em>hub</em>, not
     * the person.
     */
    public boolean acceptInboundProber(EligibilityProof proof, int adminOverlap,
                                       NullifierRegistry registry, MemberCredentialIssuer issuer,
                                       byte[] nonceCommitment, String approvingAdminUserId,
                                       Instant now) {
        // PSEUDO-CODE
        // 1. IF approvingAdminUserId lacks MANAGE_AUTHENTICATION here -> RETURN false
        // 2. result = ProberEligibility.checkInbound(proof, localHub, own issuer key,
        //                                            adminOverlap, registry, issuer,
        //                                            schedule, today, now)
        //    IF NOT permitsLink(result) -> log PROBER_REFUSED(result); RETURN false
        // 3. record inbound link keyed by proof.linkPseudonym, with
        //    proof.auditingHubKeyFingerprint, nonceCommitment and mode
        //    registry.assign(proof.proberPseudonym, proof.auditingHubKeyFingerprint)
        // 4. start sending this hub's signed tree heads to the auditing hub on sync
        // 5. log PROBER_ACCEPTED (auditing hub key fingerprint, link pseudonym)
        //    // Never a user id: there is none to log.
        // 6. RETURN true
        return false;
    }

    // --- the daily run -----------------------------------------------------

    /**
     * One day's authentication of every outbound peer. Replay always; organic
     * and synthetic only for links in FULL mode.
     */
    public List<AuditRun> runDaily(LocalDate day, Instant now) {
        // PSEUDO-CODE
        //
        // 1. PRECONDITIONS
        //    IF NOT schedule.enabled OR web.outbound empty -> RETURN empty
        //    IF NOT corpus.verify(...) -> synthetic stream off today; raise finding
        //    FOR EACH link IN web.outbound WHERE state != REVOKED
        //       proof = prober's device presents today's credential for link.subject
        //       result = peer's checkInbound(proof, ...)
        //       IF NOT permitsLink(result)
        //          link.transition(INELIGIBLE); log AUTH_LINK_INELIGIBLE; skip it
        //       // Re-proved daily. Credentials expire daily and are not
        //       // issued to admins, so promotion in the target ends the link
        //       // the same day, as before — now without the target learning
        //       // which member was promoted out of the prober role.
        //
        // 2. REPLAY (every link)
        //    head = latest head received from link.subject for day - 1
        //    IF head absent -> nothing today; dormancy counter advances
        //    size = link.mode == REPLAY_ONLY ? smallHub weekly budget
        //                                    : schedule.replaySampleSize
        //    nonce = replay.revealNonce(link, head.day)
        //    openings = request openings for sampleIndices(head, nonce, size), via sync
        //    run = replay.replay(link, head, openings, nonce, size, now)
        //    web.record(run, now)
        //
        // 3. ORGANIC (FULL links; happens continuously, collected here)
        //    FOR EACH OrganicProbe forwarded by the prober's device for link.subject
        //       ledger.recordOrganic(probe.toScore(prober))
        //       IF probe.inclusionChecked
        //          anomaly = replay.checkReceipt(link.subject, probe.receipt, proof)
        //          IF anomaly -> web.record(run with anomaly, now)
        //
        // 4. SYNTHETIC (FULL links, scheduled; see scheduleSynthetic)
        //    runs recorded as each probe resolves, not batched here
        //
        // 5. web.refreshBonds(now)
        //
        // 6. RETURN runs
        return null;
    }

    /**
     * Plans the next synthetic probe for one FULL-mode link. Called when the
     * previous one resolves, and on startup.
     */
    public Instant scheduleSynthetic(AuthLink link, int peerTrafficBand, Instant now,
                                     java.util.random.RandomGenerator rng) {
        // PSEUDO-CODE
        // IF schedule.modeFor(peerTrafficBand, link.eligibility) != FULL -> RETURN null
        // rate = schedule.syntheticRatePerDay(peerTrafficBand)
        // RETURN schedule.nextSyntheticAt(now, rate, rng)
        return null;
    }

    /**
     * Sends one synthetic probe when its time comes. PASS-side only: benign,
     * protected speech, or near-miss. Run locally first, then sent to the
     * peer under the prober's ordinary membership, where it is subject to the
     * ordinary rate limit and — if held — to ordinary moderation, like anyone's
     * question.
     */
    public AuditRun sendSynthetic(AuthLink link, LocalDate day, long seed, Instant now) {
        // PSEUDO-CODE
        // probe = prober.generateSynthetic(corpus, day, seed)
        //    // Never SUPPLY_SIGNAL. See TrustProbe.sendableToPeer.
        // local = own QueryService.ask(probe as HubQuery) -> censor behaviour only
        // peer  = send as ordinary HubQuery under the prober's membership in
        //         link.subject; discard any matches unread
        // score = prober.score(probe, local, peer)
        // ledger.record(probe, peer, score)
        // probe.forgetText()
        // run = AuditRun(kind SYNTHETIC, ...); web.record(run, now)
        // RETURN run
        return null;
    }

    /**
     * Per-run statistics. Scores each side against the corpus (synthetic) or
     * the pinned model (replay, organic) and attributes before concluding.
     */
    public List<AuditAnomaly> analyse(AuditRun run) {
        // PSEUDO-CODE
        // SWITCH run.kind
        //    REPLAY    -> anomalies are produced by ReplayAuditor.replay directly
        //    ORGANIC   -> UNLOGGED_DECISION from receipts; OVER_BLOCKING from
        //                 scores, corroborating only
        //    SYNTHETIC -> FOR EACH scoreable score
        //                    IF score.isPeerOverBlock() -> anomaly(OVER_BLOCKING, PEER)
        //                    IF attribution == LOCAL    -> anomaly(kind, LOCAL); shown first
        // IF peer confidences degenerate across the ledger window
        //    -> anomaly(DEGENERATE_CONFIDENCE, PEER)
        // IF peer pin differs -> anomaly(PIN_DIVERGENCE), corroborating only
        // RETURN anomalies
        return null;
    }

    // --- disclosure -------------------------------------------------------

    /**
     * Tells a peer what was found. Manual, per finding, and off every
     * automatic path. For replay findings the evidence is the peer's own
     * signed leaf and inclusion proof alongside this hub's replay verdict,
     * which the peer can check itself; no plaintext is sent back, since the
     * peer already holds it. For synthetic findings, the regenerated probe
     * texts cited, which should then be treated as spent.
     *
     * <p>Disclosure never includes anything from an organic probe: that is the
     * prober's own question, and sending it would identify them.
     */
    public boolean disclose(AuditRun run, List<AuditAnomaly> selected, String byAdminUserId) {
        // PSEUDO-CODE
        // 1. IF byAdminUserId lacks MANAGE_AUTHENTICATION here -> RETURN false
        // 2. IF run.kind == ORGANIC -> RETURN false
        // 3. SHOW THE COST: synthetic seeds cited are spent for this peer
        // 4. send anomaly kinds, leaf indices / regenerated synthetic texts,
        //    and both sides' decisions. Never the corpus, never other peers'.
        // 5. run.disclosed = true
        // 6. RETURN true
        return false;
    }

    /** Findings the admin must be shown, own-hub faults first. */
    public List<AuditAnomaly> report(Instant since) {
        // TODO: pseudo-code
        return null;
    }

    // --- accessors --------------------------------------------------------

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
