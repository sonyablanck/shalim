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

    private String ownerKeyFingerprint;

    /** Links from this hub to peers. */
    private List<AuthLink> outbound;

    /**
     * Links from peers to this hub, as the peers reported them during bond
     * exchange. Held so standing can be computed; never re-published.
     */
    private List<AuthLink> inbound;

    private List<AuthBond> bonds;

    private List<AuditRun> runs;

    private ProbeLedger ledger;

    public WebOfTrust() {
        // TODO: pseudo-code
    }

    public WebOfTrust(String ownerKeyFingerprint, ProbeLedger ledger) {
        // TODO: pseudo-code
    }

    // --- setting up -------------------------------------------------------

    /**
     * Sets up authentication of a peer. The consenting admin must be able to
     * present a current {@link MemberCredential} there. Their user id is
     * recorded on this hub's copy of the link only.
     */
    public AuthLink setUp(String peerKeyFingerprint, String probingAdminUserId,
                          AuditSchedule.Mode mode, byte[] nonceSecret, Instant now) {
        // PSEUDO-CODE
        // IF an outbound link to peer exists and is not REVOKED -> RETURN it
        // link = new AuthLink(owner, peer, probingAdminUserId, mode, now)  // PENDING
        // link.nonceSecret = nonceSecret
        // outbound.add(link)
        // log AUTH_LINK_SET_UP with peer key fingerprint and mode
        // RETURN link
        //    // PENDING counts for nothing yet. It becomes ACTIVE after its first
        //    // passing window, so a new hub cannot unlock itself on the strength
        //    // of a link that has not measured anything.
        return null;
    }

    // --- deciding ---------------------------------------------------------

    /**
     * Re-evaluates one outbound link against its rolling window. Called after
     * every run of any kind. This is the only place a link changes state.
     *
     * <p>The window now reads three evidence streams with different weights.
     * Replay findings are near-proof, because the model is deterministic and
     * the peer committed before the sample was drawn; they need a handful of
     * leaves, not hundreds of probes. Synthetic findings are statistical, as
     * before, and now cover over-blocking only. Organic findings corroborate,
     * except an unlogged receipt, which is conclusive.
     */
    public AuthLink.State assess(String peerKeyFingerprint, Instant now) {
        // PSEUDO-CODE
        //
        // window = ledger.forPeer(peer, since = now - policy.meetingRequestRetentionDays)
        //    // The window IS the retention period. A revocation must be
        //    // decided on evidence that is still there to appeal against.
        //
        // 1. CONCLUSIVE EVIDENCE (any one suffices to suspend)
        //    conclusive = window anomalies WHERE kind IN
        //       (REPLAY_MISMATCH, EQUIVOCATION, UNLOGGED_DECISION, OPENING_WITHHELD)
        //       AND attribution == PEER
        //    // OPENING_WITHHELD counts only after a retry on the next sync:
        //    // a flat battery mid-sync is not a refusal.
        //
        // 2. POWER
        //    replayed = scoreable replayed leaves in window
        //    passSide = scoreable synthetic PASS-side scores in window
        //    IF conclusive empty
        //       AND replayed < minReplayLeaves
        //       AND (link.mode == REPLAY_ONLY OR passSide < minPassProbes)
        //       -> IF link.state == ACTIVE AND no scoreable evidence for dormancyDays
        //             RETURN transition(DORMANT)
        //                // Usually a blackout: no heads arriving. Dormant stops
        //                // counting for search but is not a revocation.
        //          RETURN unchanged
        //    // Eight replayed leaves a day give ~110 per fortnight. One
        //    // mismatch outside tolerance is enough to act on, because an
        //    // honest pinned model never produces one.
        //
        // 3. ATTRIBUTE
        //    IF replay runs were VOID for pin mismatch on our side, or
        //       synthetic LOCAL faults materially exceed PEER faults
        //       raise CENSOR_INTEGRITY finding against THIS hub
        //       RETURN unchanged
        //
        // 4. MEASURE OVER-BLOCKING (FULL links only)
        //    over = synthetic scores WHERE isPeerOverBlock()
        //    overFailing = over.rate significantly exceeds baseline (p < 0.01)
        //    organicOver = organic scores WHERE isPeerOverBlock()
        //    // Organic over-blocking corroborates: it can tip a borderline
        //    // synthetic result into SUSPENDED, never into REVOKED alone.
        //
        // 5. DECIDE
        //    failing = conclusive non-empty OR overFailing
        //    IF NOT failing
        //       IF state IN (PENDING, SUSPENDED, DORMANT) -> transition(ACTIVE)
        //       link.lastPassedAt = now
        //       RETURN ACTIVE
        //    IF state == ACTIVE -> transition(SUSPENDED); notify THIS hub's admins
        //    IF state == SUSPENDED AND suspended for >= suspensionDays
        //          AND still failing on evidence dated AFTER suspension began
        //       -> revoke(link, now)
        //       // For replay, "fresh evidence" means a mismatch on a later
        //       // day's tree. One bad day cannot carry a revocation alone.
        //    IF state == PENDING -> RETURN PENDING
        //
        // 6. RECORD every transition in HubLog by key fingerprint only
        return null;
    }

    /**
     * Revokes one link. Removes exactly one direction toward exactly one
     * peer; cannot cascade.
     */
    public boolean revoke(AuthLink link, Instant now) {
        // PSEUDO-CODE
        // link.transition(REVOKED, now, revocationId = new id)
        // pin the ledger entries behind it until any appeal closes
        // dissolve the bond with that peer, if any
        // log AUTH_LINK_REVOKED (peer key fingerprint, revocation id)
        // Do NOT message the peer. Disclosure is PeerAuditor.disclose, manual.
        //    // Silence here is still the default, but it is thinner protection
        //    // than before: the peer will notice a bond proof has gone.
        return false;
    }

    /** Re-forms or lapses bonds after links change. Needs a live exchange with each peer. */
    public int refreshBonds(Instant now) {
        // PSEUDO-CODE
        // FOR EACH peer WITH outbound and inbound links
        //    bond = AuthBond.formIfMutual(out, in, now)
        //    IF bond -> replace existing; ELSE let existing expire
        // RETURN number of current bonds
        return 0;
    }

    // --- what other code may read ------------------------------------------

    /**
     * This hub's standing, from which member privileges are capped. See
     * {@link org.shalim.hub.HubStanding} for the rules.
     */
    public org.shalim.hub.HubStanding standing(org.shalim.hub.HubPolicy policy, Instant now) {
        // PSEUDO-CODE
        // RETURN HubStanding.compute(
        //    outboundCounting = outbound WHERE counts(now),
        //    inboundCounting  = inbound  WHERE counts(now),
        //    everUnlocked, allInboundRevoked, policy.unlockBasis, now)
        return null;
    }

    /** Current bond count. What search thresholds are compared against. */
    public int currentBondCount(Instant now) {
        // TODO: pseudo-code
        return 0;
    }

    /** Anonymised proofs for this hub's card. See {@link BondProof}. */
    public List<BondProof> publishableProofs(List<byte[]> ringOfListedIssuerKeys, Instant now) {
        // TODO: pseudo-code
        return null;
    }

    /**
     * Whether a hub's absence from search means anything. Still no: a hub
     * below threshold may be new, may be waiting on a reciprocity invite, may
     * have gone dormant in a blackout, or may have lost a bond to revocation.
     * Nothing on the card distinguishes these, and nothing may be added that
     * would.
     */
    public boolean absenceIsEvidence() {
        return false;
    }

    // --- maintenance ------------------------------------------------------

    public boolean record(AuditRun run, Instant now) {
        // PSEUDO-CODE
        // runs.add(run)
        // IF run.verdict() == VOID -> discard its outcomes; RETURN false
        // IF run.kind == ORGANIC -> keep scores only; the texts were never here
        // assess(run.peerKeyFingerprint, now)
        // RETURN whether the link changed state
        return false;
    }

    /** Drops runs and non-appealed revocations past the ledger's retention. */
    public int prune(org.shalim.hub.HubPolicy policy, Instant now) {
        // TODO: pseudo-code
        return 0;
    }

    /** Duress path, alongside HubLog.wipe and ProbeLedger.wipe. */
    public void wipe() {
        // TODO: pseudo-code
    }

    // --- accessors --------------------------------------------------------

    public String getOwnerKeyFingerprint() {
        return ownerKeyFingerprint;
    }

    public List<AuthLink> getOutbound() {
        return outbound;
    }

    public List<AuthLink> getInbound() {
        return inbound;
    }

    public List<AuthBond> getBonds() {
        return bonds;
    }

    public List<AuditRun> getRuns() {
        return runs;
    }

    public ProbeLedger getLedger() {
        return ledger;
    }
}
