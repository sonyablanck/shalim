package org.shalim.trust;

import java.time.Instant;
import java.util.List;

/**
 * One hub's authentication state: the peers it authenticates ({@link AuthLink}s
 * out), the peers that authenticate it (links in, learned during bond
 * exchange), the {@link AuthBond}s where both directions hold, and the
 * decisions to keep or revoke.
 *
 * <h2>What changed, and what it costs</h2>
 *
 * <p>The earlier design kept this class deliberately powerless: a private
 * notebook of vouches with no path to membership, discovery or anything a
 * member could feel, so that a hostile hub withholding its vouch achieved
 * nothing. Authentication now does three things:
 * <ol>
 *   <li>A hub with no authentication relationship caps every member except
 *       its admins at GUEST — see {@link org.shalim.hub.HubStanding}.</li>
 *   <li>Bonds are counted on the hub's public card, and hub search hides hubs
 *       below a threshold of 1–5 bonds (default 2).</li>
 *   <li>Revocation removes a link, which can remove a bond, which can drop a
 *       hub out of search.</li>
 * </ol>
 * That makes revocation a lever, and a hostile hub that has bonded with a
 * community can pull it. The guards against that are all in {@link #assess}:
 * revocation needs evidence attributed to the peer — a replayed decision the
 * pinned model contradicts, a split or incomplete decision log, or
 * statistically significant over-blocking of protected speech — over a rolling
 * window, surviving a suspension period — and a single
 * revocation can only ever remove one link. The README lists what these guards
 * do not cover.
 *
 * <h2>What it still is not</h2>
 *
 * <p><strong>Not transitive.</strong> A peer's links confer nothing. Bonds are
 * counted, never chained.
 *
 * <p><strong>Not a distrust list.</strong> A revoked link is recorded here so
 * it can be appealed, with a pointer into the {@link ProbeLedger}; it is pruned
 * with the ledger. Nothing about a revocation is published: the peer's card
 * simply carries one fewer {@link BondProof}.
 *
 * <p><strong>Not a person-level signal.</strong> Losing authentication caps a
 * hub's members at GUEST <em>inside that hub</em> only. It never touches their
 * memberships elsewhere, their attestations, or their earned skills.
 */
public class WebOfTrust {

    /** Minimum and maximum a searcher may ask for; 0 is never accepted. */
    public static final int MIN_SEARCH_BONDS = 1;
    public static final int MAX_SEARCH_BONDS = 5;
    public static final int DEFAULT_SEARCH_BONDS = 2;

    /** Significance needed before statistical over-blocking counts. One in a hundred. */
    static final double SIGNIFICANCE = 0.01;

    /** Where state changes are recorded. Key fingerprints only, never hub ids. */
    @FunctionalInterface
    public interface Events {
        void record(org.shalim.hub.HubLog.EventType type, String peerKeyFingerprint, String detail, Instant now);
    }

    private final String ownerKeyFingerprint;

    /** Links from this hub to peers. */
    private final List<AuthLink> outbound = new java.util.ArrayList<>();

    /**
     * Links from peers to this hub, as this hub holds them: by link pseudonym,
     * with the authenticating hub's latest signed statement. Never re-published.
     */
    private final List<AuthLink> inbound = new java.util.ArrayList<>();

    private final List<AuthBond> bonds = new java.util.ArrayList<>();

    private final List<AuditRun> runs = new java.util.ArrayList<>();

    private final ProbeLedger ledger;

    /** Findings against this hub's own censor, raised by audits. Shown to its admins first. */
    private final List<AuditAnomaly> localFindings = new java.util.ArrayList<>();

    private AuditSchedule schedule = new AuditSchedule();
    private int retentionDays = 14;
    private Events events = (t, p, d, n) -> { };

    /** When this hub was first unlocked by an inbound link. Standing fails open after this. */
    private Instant everUnlockedAt;

    /** Provisional clocks for this hub; null means it is never provisional. */
    private org.shalim.hub.ProvisionalStatus provisional;

    public WebOfTrust(String ownerKeyFingerprint, ProbeLedger ledger) {
        this.ownerKeyFingerprint = ownerKeyFingerprint;
        this.ledger = ledger;
    }

    /** Window and retention come from the hub's schedule and policy. */
    public WebOfTrust configure(AuditSchedule schedule, org.shalim.hub.HubPolicy policy) {
        if (schedule != null) {
            this.schedule = schedule;
        }
        if (policy != null) {
            this.retentionDays = policy.getMeetingRequestRetentionDays();
        }
        return this;
    }

    public WebOfTrust withEvents(Events events) {
        this.events = events == null ? (t, p, d, n) -> { } : events;
        return this;
    }

    public WebOfTrust withProvisional(org.shalim.hub.ProvisionalStatus provisional) {
        this.provisional = provisional;
        return this;
    }

    // --- setting up -------------------------------------------------------

    /**
     * Records authentication of a peer and starts its nonce chain. The
     * probing admin's user id is recorded on this hub's copy of the link only.
     * PENDING counts for nothing yet: it becomes ACTIVE after its first passing
     * window, so a link that has measured nothing unlocks nothing.
     */
    public synchronized AuthLink setUp(String peerKeyFingerprint, byte[] peerPublicKey, String probingAdminUserId,
                                       String linkPseudonym, AuditSchedule.Mode mode,
                                       ProberEligibility.Result eligibility, Instant now) {
        AuthLink existing = outboundTo(peerKeyFingerprint);
        if (existing != null && !existing.isRevoked() && existing.getState() != AuthLink.State.INELIGIBLE) {
            return existing;
        }
        if (existing != null) {
            outbound.remove(existing);
        }
        AuthLink link = new AuthLink(ownerKeyFingerprint, peerKeyFingerprint, probingAdminUserId, mode, now);
        link.setSubjectPublicKey(peerPublicKey);
        link.setLinkPseudonym(linkPseudonym);
        link.setEligibility(eligibility, now);
        // The chain starts yesterday so that today, the setup day, is the first day with a nonce.
        link.startNonceChain(java.time.LocalDate.ofInstant(now, java.time.ZoneOffset.UTC).minusDays(1));
        outbound.add(link);
        events.record(org.shalim.hub.HubLog.EventType.AUTH_LINK_SET_UP, peerKeyFingerprint, mode.name(), now);
        return link;
    }

    /** Target side: records a link another hub holds on this one. */
    public synchronized void recordInbound(AuthLink link) {
        inbound.removeIf(l -> l.getAuthenticatorKeyFingerprint().equals(link.getAuthenticatorKeyFingerprint()));
        inbound.add(link);
    }

    /** Target side: applies a statement from an authenticating hub. */
    public synchronized boolean applyStatement(LinkStatement statement, Instant now) {
        for (AuthLink l : inbound) {
            if (l.getAuthenticatorKeyFingerprint().equals(statement.getAuthenticatorKeyFingerprint())) {
                boolean wasAllRevoked = allInboundRevoked();
                boolean ok = l.applyStatement(statement, now);
                if (ok && !wasAllRevoked && allInboundRevoked() && provisional != null) {
                    provisional.inboundRevoked(now);
                }
                return ok;
            }
        }
        return false;
    }

    // --- deciding ---------------------------------------------------------

    /**
     * Re-evaluates one outbound link against its rolling window. Called after
     * every run of any kind. This is the only place a link changes state.
     *
     * <p>Three streams, three weights. Replay findings are near-proof: the
     * model is deterministic and the peer committed before the sample was
     * drawn, so one verified mismatch suffices. Synthetic findings are
     * statistical and cover over-blocking only. Organic findings corroborate,
     * except an unlogged receipt, which is conclusive.
     */
    public synchronized AuthLink.State assess(String peerKeyFingerprint, Instant now) {
        AuthLink link = outboundTo(peerKeyFingerprint);
        if (link == null) {
            return null;
        }
        if (link.isRevoked() || link.getState() == AuthLink.State.INELIGIBLE) {
            return link.getState();
        }
        // The window IS the retention period: a revocation must be decided on
        // evidence still there to appeal against.
        Instant since = now.minus(java.time.Duration.ofDays(retentionDays));
        List<AuditRun> window = runsFor(peerKeyFingerprint, since);

        // Attribute first. If the audits keep finding this hub, stop judging others.
        long localFaults = window.stream().filter(r -> r.verdict() == AuditRun.Verdict.LOCAL_FAULT).count();
        long failed = window.stream().filter(r -> r.verdict() == AuditRun.Verdict.FAILED).count();
        if (localFaults > 0 && localFaults >= failed) {
            raiseLocal("Audits of another hub keep finding this hub's own screening is the one out of line.", now);
            return link.getState();
        }

        // 1. Conclusive evidence.
        List<AuditAnomaly> conclusive = conclusive(window, null);

        // 2. Power.
        boolean smallHub = link.getEligibility() == ProberEligibility.Result.ANONYMITY_SET_TOO_SMALL;
        int replayed = window.stream().filter(r -> r.getKind() == AuditRun.Kind.REPLAY)
                .mapToInt(AuditRun::getReplayRealScored).sum();
        boolean full = link.getMode() == AuditSchedule.Mode.FULL;
        OverBlocking ob = full ? overBlocking(window) : OverBlocking.NONE;

        if (conclusive.isEmpty()) {
            Instant lastEvidence = link.getLastEvidenceAt() != null ? link.getLastEvidenceAt() : link.getEstablishedAt();
            if (link.getState() == AuthLink.State.ACTIVE
                    && lastEvidence.isBefore(now.minus(java.time.Duration.ofDays(schedule.getDormancyDays())))) {
                // Usually a blackout: no heads arriving. Not a revocation.
                return change(link, AuthLink.State.DORMANT, now, null);
            }
            if (link.getState() == AuthLink.State.DORMANT && !lastEvidence.isAfter(link.getStateChangedAt())) {
                return AuthLink.State.DORMANT; // wakes only on evidence that arrived after it slept
            }
            boolean enoughReplay = replayed >= schedule.minReplayLeavesFor(smallHub);
            boolean enoughPass = full && ob.passSide >= schedule.getMinPassProbes();
            if (!enoughReplay && !enoughPass && !ob.corroboratedByOrganic) {
                return link.getState();
            }
        }

        // 5. Decide.
        boolean failing = !conclusive.isEmpty() || ob.significant;
        boolean suspendWorthy = failing || ob.corroboratedByOrganic;
        if (!suspendWorthy) {
            link.markPassed(now);
            if (link.getState() != AuthLink.State.ACTIVE) {
                return change(link, AuthLink.State.ACTIVE, now, null);
            }
            return AuthLink.State.ACTIVE;
        }
        switch (link.getState()) {
            case PENDING:
                return AuthLink.State.PENDING; // never counted, so nothing to suspend
            case ACTIVE:
            case DORMANT:
                return change(link, AuthLink.State.SUSPENDED, now, null);
            case SUSPENDED:
                Instant suspendedAt = link.getStateChangedAt();
                boolean served = !now.isBefore(suspendedAt.plus(java.time.Duration.ofDays(schedule.getSuspensionDays())));
                // Fresh evidence: dated after suspension began, and for replay
                // on a later day's record than anything before it. One bad day
                // cannot carry a revocation alone. Organic corroboration never can.
                boolean fresh = !conclusive(window, suspendedAt).isEmpty()
                        || overBlocking(runsFor(peerKeyFingerprint, suspendedAt)).significant;
                if (served && fresh) {
                    revoke(link, now);
                }
                return link.getState();
            default:
                return link.getState();
        }
    }

    /**
     * Revokes one link. Removes exactly one direction toward exactly one
     * peer; cannot cascade. The peer learns only the state, through the next
     * {@link LinkStatement}; findings are disclosed by hand or not at all.
     */
    public synchronized boolean revoke(AuthLink link, Instant now) {
        if (link == null || link.isRevoked()) {
            return false;
        }
        String revocationId = org.shalim.crypto.Bytes.randomId();
        Instant since = now.minus(java.time.Duration.ofDays(retentionDays));
        ledger.pin(revocationId, ledger.forPeer(link.getSubjectKeyFingerprint(), since));
        change(link, AuthLink.State.REVOKED, now, revocationId);
        bonds.removeIf(b -> b.otherParty(ownerKeyFingerprint).equals(link.getSubjectKeyFingerprint()));
        return true;
    }

    /** The revoked hub appealed: the evidence is kept until the appeal closes. */
    public synchronized boolean openAppeal(String peerKeyFingerprint) {
        AuthLink link = outboundTo(peerKeyFingerprint);
        if (link == null || !link.isRevoked()) {
            return false;
        }
        link.openAppeal();
        ledger.openAppeal(link.getRevocationId());
        return true;
    }

    /** Closes an appeal. Upheld restores the link to ACTIVE; either way the pinned evidence is released. */
    public synchronized boolean closeAppeal(String peerKeyFingerprint, boolean upheld, Instant now) {
        AuthLink link = outboundTo(peerKeyFingerprint);
        if (link == null || !link.isUnderAppeal()) {
            return false;
        }
        ledger.closeAppeal(link.getRevocationId());
        link.closeAppeal();
        if (upheld) {
            change(link, AuthLink.State.ACTIVE, now, null);
        }
        return true;
    }

    /** Marks a link INELIGIBLE: the prober could not present today. Not a finding about anyone. */
    public synchronized void ineligible(AuthLink link, ProberEligibility.Result result, Instant now) {
        link.setEligibility(result, now);
        change(link, AuthLink.State.INELIGIBLE, now, null);
    }

    /**
     * Forms or lapses bonds after links change. A bond needs both directions
     * and both signatures; the exchange that collects the other signature is
     * stage 5's. Returns the number of bonds current now.
     */
    public synchronized int refreshBonds(Instant now) {
        bonds.removeIf(b -> b.getExpiresAt() != null && !now.isBefore(b.getExpiresAt()));
        return currentBondCount(now);
    }

    /** Adds a bond both sides have signed. */
    public synchronized boolean addBond(AuthBond bond, Instant now) {
        if (bond == null || !bond.isCurrent(now)) {
            return false;
        }
        String peer = bond.otherParty(ownerKeyFingerprint);
        bonds.removeIf(b -> b.otherParty(ownerKeyFingerprint).equals(peer));
        bonds.add(bond);
        events.record(org.shalim.hub.HubLog.EventType.AUTH_BOND_FORMED, peer, null, now);
        return true;
    }

    // --- what other code may read ------------------------------------------

    /**
     * This hub's standing, from which member privileges are capped. Inbound
     * links only count while the authenticating hub's statement is current.
     */
    public synchronized org.shalim.hub.HubStanding standing(org.shalim.hub.HubPolicy policy, Instant now) {
        int out = (int) outbound.stream().filter(l -> l.counts(now)).count();
        int in = (int) inbound.stream().filter(l -> l.countsInbound(now)).count();
        org.shalim.hub.HubStanding s = org.shalim.hub.HubStanding.compute(out, in, currentBondCount(now),
                everUnlockedAt, allInboundRevoked(), policy == null ? null : policy.getUnlockBasis(), provisional, now);
        if (everUnlockedAt == null && s.getEverUnlockedAt() != null) {
            everUnlockedAt = s.getEverUnlockedAt();
        }
        return s;
    }

    /** Current bond count. What search thresholds are compared against. */
    public synchronized int currentBondCount(Instant now) {
        return (int) bonds.stream().filter(b -> b.isCurrent(now)).count();
    }

    /** Anonymised proofs for this hub's card. Stage 5. */
    public List<BondProof> publishableProofs(List<byte[]> ringOfListedIssuerKeys, Instant now) {
        return List.of();
    }

    /**
     * Whether a hub's absence from search means anything. Still no: a hub
     * below threshold may be new, may be waiting on a reciprocity invite, may
     * have gone dormant in a blackout, or may have lost a bond to revocation.
     */
    public boolean absenceIsEvidence() {
        return false;
    }

    /** Findings the admin must be shown, own-hub faults first. */
    public synchronized List<AuditAnomaly> findings(Instant since) {
        List<AuditAnomaly> out = new java.util.ArrayList<>();
        localFindings.stream().filter(a -> !a.getObservedAt().isBefore(since)).forEach(out::add);
        for (AuditRun r : runs) {
            if (r.getStartedAt() != null && !r.getStartedAt().isBefore(since)) {
                r.flagged().stream().filter(AuditAnomaly::concernsAuditor).forEach(out::add);
            }
        }
        for (AuditRun r : runs) {
            if (r.getStartedAt() != null && !r.getStartedAt().isBefore(since)) {
                r.flagged().stream().filter(a -> !a.concernsAuditor()).forEach(out::add);
            }
        }
        return out;
    }

    // --- maintenance ------------------------------------------------------

    /** Records a run and re-assesses its peer. Returns whether the link changed state. */
    public synchronized boolean record(AuditRun run, Instant now) {
        runs.add(run);
        AuthLink link = outboundTo(run.getPeerKeyFingerprint());
        if (link == null) {
            return false;
        }
        AuditRun.Verdict v = run.verdict();
        if (v == AuditRun.Verdict.VOID) {
            if (run.isPinMismatch()) {
                // Corroborating only: nobody yet knows which side changed.
                raiseLocal("Another hub's screening records came from a different censor release from this hub's.",
                        now);
            }
            return false;
        }
        if (hasEvidence(run)) {
            link.markEvidence(now);
        }
        AuthLink.State before = link.getState();
        assess(run.getPeerKeyFingerprint(), now);
        return before != link.getState();
    }

    /** Drops runs and revoked links past retention, except those under appeal. */
    public synchronized int prune(org.shalim.hub.HubPolicy policy, Instant now) {
        int days = policy == null ? retentionDays : policy.getMeetingRequestRetentionDays();
        Instant cutoff = now.minus(java.time.Duration.ofDays(days));
        java.util.Set<String> appealed = new java.util.HashSet<>();
        outbound.stream().filter(AuthLink::isUnderAppeal).forEach(l -> appealed.add(l.getSubjectKeyFingerprint()));
        int before = runs.size();
        runs.removeIf(r -> r.getStartedAt() != null && r.getStartedAt().isBefore(cutoff)
                && !appealed.contains(r.getPeerKeyFingerprint()));
        int n = before - runs.size();
        int linksBefore = outbound.size();
        outbound.removeIf(l -> l.isRevoked() && !l.isUnderAppeal() && l.getStateChangedAt().isBefore(cutoff));
        localFindings.removeIf(a -> a.getObservedAt().isBefore(cutoff));
        return n + (linksBefore - outbound.size()) + ledger.prune(policy, now);
    }

    /** Duress path, alongside HubLog.wipe and ProbeLedger.wipe. */
    public synchronized void wipe() {
        outbound.forEach(l -> org.shalim.crypto.Bytes.wipe(l.nonceSecret()));
        outbound.clear();
        inbound.clear();
        bonds.clear();
        runs.clear();
        localFindings.clear();
        ledger.wipe();
    }

    // --- internals --------------------------------------------------------

    public synchronized AuthLink outboundTo(String peerKeyFingerprint) {
        for (AuthLink l : outbound) {
            if (l.getSubjectKeyFingerprint().equals(peerKeyFingerprint)) {
                return l;
            }
        }
        return null;
    }

    public synchronized AuthLink inboundFrom(String authenticatorKeyFingerprint) {
        for (AuthLink l : inbound) {
            if (l.getAuthenticatorKeyFingerprint().equals(authenticatorKeyFingerprint)) {
                return l;
            }
        }
        return null;
    }

    private boolean allInboundRevoked() {
        return !inbound.isEmpty() && inbound.stream().allMatch(AuthLink::isRevoked);
    }

    private AuthLink.State change(AuthLink link, AuthLink.State to, Instant now, String ref) {
        link.transition(to, now, ref);
        org.shalim.hub.HubLog.EventType type = switch (to) {
            case ACTIVE -> org.shalim.hub.HubLog.EventType.AUTH_LINK_ACTIVATED;
            case SUSPENDED -> org.shalim.hub.HubLog.EventType.AUTH_LINK_SUSPENDED;
            case REVOKED -> org.shalim.hub.HubLog.EventType.AUTH_LINK_REVOKED;
            case DORMANT -> org.shalim.hub.HubLog.EventType.AUTH_LINK_DORMANT;
            case INELIGIBLE -> org.shalim.hub.HubLog.EventType.AUTH_LINK_INELIGIBLE;
            case PENDING -> null;
        };
        if (type != null) {
            events.record(type, link.getSubjectKeyFingerprint(), ref, now);
        }
        return link.getState();
    }

    private List<AuditRun> runsFor(String peer, Instant since) {
        List<AuditRun> out = new java.util.ArrayList<>();
        for (AuditRun r : runs) {
            if (peer.equals(r.getPeerKeyFingerprint()) && r.getStartedAt() != null && !r.getStartedAt().isBefore(since)
                    && r.verdict() != AuditRun.Verdict.VOID) {
                out.add(r);
            }
        }
        return out;
    }

    /**
     * Conclusive peer-attributed anomalies in the window. With {@code after}
     * set, only those observed after it, and for replay only on a day later
     * than any conclusive day observed before it.
     */
    private List<AuditAnomaly> conclusive(List<AuditRun> window, Instant after) {
        List<AuditAnomaly> all = new java.util.ArrayList<>();
        for (AuditRun r : window) {
            for (AuditAnomaly a : r.getAnomalies()) {
                if (a.isConclusive()) {
                    all.add(a);
                }
            }
        }
        if (after == null) {
            return all;
        }
        java.time.LocalDate lastEarlierDay = null;
        for (AuditAnomaly a : all) {
            if (a.getObservedAt() != null && !a.getObservedAt().isAfter(after) && a.getDay() != null
                    && (lastEarlierDay == null || a.getDay().isAfter(lastEarlierDay))) {
                lastEarlierDay = a.getDay();
            }
        }
        List<AuditAnomaly> fresh = new java.util.ArrayList<>();
        for (AuditAnomaly a : all) {
            if (a.getObservedAt() != null && a.getObservedAt().isAfter(after)
                    && (a.getDay() == null || lastEarlierDay == null || a.getDay().isAfter(lastEarlierDay))) {
                fresh.add(a);
            }
        }
        return fresh;
    }

    private record OverBlocking(int passSide, int over, boolean significant, boolean corroboratedByOrganic) {
        static final OverBlocking NONE = new OverBlocking(0, 0, false, false);
    }

    /**
     * Over-blocking of PASS-side synthetic probes, as a one-sided binomial test
     * against the baseline rate at which an honest censor blocks them. Organic
     * over-blocking can tip a borderline result (p &lt; 0.05) into suspension,
     * never into revocation.
     */
    private OverBlocking overBlocking(List<AuditRun> window) {
        int n = 0;
        int k = 0;
        int organicOver = 0;
        for (AuditRun r : window) {
            for (DifferenceScore d : r.getScores()) {
                if (!d.isScoreable()) {
                    continue;
                }
                if (d.getSource() == DifferenceScore.Source.ORGANIC) {
                    if (d.isPeerOverBlock()) {
                        organicOver++;
                    }
                    continue;
                }
                if (d.getIntent() == TrustProbe.Intent.BENIGN || d.getIntent() == TrustProbe.Intent.PROTECTED_SPEECH) {
                    if (!d.isLocalMetExpectation()) {
                        continue; // our own miss is not evidence about the peer
                    }
                    n++;
                    if (d.isPeerOverBlock()) {
                        k++;
                    }
                }
            }
        }
        double base = schedule.getOverBlockBaseline();
        double p = binomialUpperTail(n, k, base);
        boolean significant = n >= schedule.getMinPassProbes() && k > n * base && p < SIGNIFICANCE;
        boolean corroborated = !significant && k > 0 && organicOver > 0 && p < 0.05;
        return new OverBlocking(n, k, significant, corroborated);
    }

    /** P(X &gt;= k) for X ~ Binomial(n, p). */
    static double binomialUpperTail(int n, int k, double p) {
        if (k <= 0) {
            return 1.0;
        }
        if (k > n) {
            return 0.0;
        }
        double sum = 0;
        for (int i = k; i <= n; i++) {
            sum += Math.exp(logChoose(n, i) + i * Math.log(p) + (n - i) * Math.log1p(-p));
        }
        return Math.min(1.0, sum);
    }

    private static double logChoose(int n, int k) {
        double r = 0;
        for (int i = 1; i <= k; i++) {
            r += Math.log(n - k + i) - Math.log(i);
        }
        return r;
    }

    private static boolean hasEvidence(AuditRun r) {
        return switch (r.getKind()) {
            case REPLAY -> r.getReplayRealScored() + r.getReplayPads() > 0 || !r.getAnomalies().isEmpty();
            case ORGANIC, SYNTHETIC -> r.getScores().stream().anyMatch(DifferenceScore::isScoreable)
                    || !r.getAnomalies().isEmpty();
        };
    }

    private void raiseLocal(String explanation, Instant now) {
        for (AuditAnomaly a : localFindings) {
            if (a.getExplanation().equals(explanation) && a.getObservedAt().isAfter(now.minus(java.time.Duration.ofDays(1)))) {
                return;
            }
        }
        localFindings.add(AuditAnomaly.of(AuditAnomaly.Kind.PIN_DIVERGENCE, AuditAnomaly.Attribution.LOCAL, null, null,
                explanation, now));
        events.record(org.shalim.hub.HubLog.EventType.CENSOR_FLAG_RAISED, null, "audit", now);
    }

    // --- accessors --------------------------------------------------------

    public String getOwnerKeyFingerprint() {
        return ownerKeyFingerprint;
    }

    public synchronized List<AuthLink> getOutbound() {
        return List.copyOf(outbound);
    }

    public synchronized List<AuthLink> getInbound() {
        return List.copyOf(inbound);
    }

    public synchronized List<AuthBond> getBonds() {
        return List.copyOf(bonds);
    }

    public synchronized List<AuditRun> getRuns() {
        return List.copyOf(runs);
    }

    public ProbeLedger getLedger() {
        return ledger;
    }

    public AuditSchedule getSchedule() {
        return schedule;
    }

    public Instant getEverUnlockedAt() {
        return everUnlockedAt;
    }
}
