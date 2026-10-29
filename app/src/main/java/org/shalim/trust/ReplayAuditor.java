package org.shalim.trust;

import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import org.shalim.hub.CensorDecisionLog;

/**
 * Checks a peer's censor by replaying a random sample of its real, committed
 * decisions through this hub's own copy of the pinned artefact. The primary
 * test of the peer's censor, and the only one that covers under-blocking.
 *
 * <h2>Why the auditor does not need to be anonymous here</h2>
 *
 * <p>The peer knows which hub is replaying it — replay requests come from the
 * auditing hub's key. That is safe, because the peer committed to its tree
 * <em>before</em> the sample was chosen and cannot change a leaf afterwards.
 * Knowing the auditor lets a dishonest hub refuse to open, which is itself a
 * finding; it does not let it pass.
 *
 * <h2>Sampling</h2>
 *
 * <p>The auditor commits to a nonce chain when the link is set up and reveals
 * one value each day only after the peer's head is signed:
 * {@code indices = sample(HMAC(nonce_day, head))}. The peer cannot predict the
 * sample when signing; the auditor cannot aim it at a particular leaf, and so
 * cannot use replay to read one member's question.
 *
 * <p>The nonce chain is a {@link org.shalim.crypto.HashChain}. The earlier
 * pseudo-code derived nonces as {@code HMAC(nonceSecret, day)} with commitment
 * {@code H(nonceSecret)}. That cannot be checked, so the auditor could have
 * picked any nonce after seeing the root. The peer now verifies every revealed
 * nonce against the chain anchor ({@link #verifyRevealedNonce}) before opening
 * anything.
 *
 * <h2>What a replay proves</h2>
 * <ul>
 *   <li>Decision or categories differ, or confidence differs by more than
 *       {@link #CONFIDENCE_TOLERANCE}: the logged decision did not come from the
 *       pinned model. {@link AuditAnomaly.Kind#REPLAY_MISMATCH}.</li>
 *   <li>The action taken does not follow from the decision (a BLOCK that was
 *       answered): the hub ran the right model and ignored it. Same kind.</li>
 *   <li>Opening refused, proof invalid, or a pad that does not open as a pad:
 *       {@link AuditAnomaly.Kind#OPENING_WITHHELD}.</li>
 *   <li>Two different signed heads for one day, seen here or reported by a
 *       member's receipt check: {@link AuditAnomaly.Kind#EQUIVOCATION}.
 *       Conclusive on its own: an honest hub never signs two roots for a day.</li>
 * </ul>
 *
 * <h2>What a replay cannot prove</h2>
 *
 * <p>That the log holds everything. A hub can route some traffic around the
 * log entirely. That is what {@link OrganicProbe} checks: members' devices
 * hold receipts for their own screenings and verify they appear in the tree.
 */
public class ReplayAuditor {

    /**
     * Confidence difference tolerated between two runs of the pinned model.
     * Non-zero because integer-quantised inference is bit-exact only on the
     * reference CPU backend; hubs are required to screen on that backend, but
     * the tolerance absorbs harmless drift. Leaves whose confidence lies
     * within the tolerance of a threshold are excluded from findings, since
     * the drift could legitimately flip the decision there.
     */
    public static final float CONFIDENCE_TOLERANCE = 0.005f;

    private String ownerKeyFingerprint;
    private org.shalim.ml.CensorEngine localCensor;
    private ProbeLedger ledger;

    public ReplayAuditor() {
        // TODO: pseudo-code
    }

    public ReplayAuditor(String ownerKeyFingerprint, org.shalim.ml.CensorEngine localCensor,
                         ProbeLedger ledger) {
        // TODO: pseudo-code
    }

    /**
     * Accepts a peer's head for a day, checking signature and chain. Keeps
     * every head so equivocation can be spotted when a receipt disagrees.
     */
    public boolean acceptHead(CensorDecisionLog.SignedTreeHead head, byte[] peerPublicKey) {
        // PSEUDO-CODE
        // IF NOT head.verify(peerPublicKey) -> RETURN false
        // prior = stored head for (peer, head.day)
        // IF prior exists AND prior.root != head.root -> anomaly(EQUIVOCATION, PEER)
        // IF head.previousHeadHash != hash(stored head for day - 1) AND that
        //    head is held -> anomaly(EQUIVOCATION, PEER)   // a dropped or rewritten day
        // store head
        // RETURN true
        return false;
    }

    /** Indices to open for one day. Deterministic in (root, nonce); never chosen by hand. */
    public static List<Long> sampleIndices(CensorDecisionLog.SignedTreeHead head, byte[] dayNonce,
                                           int sampleSize) {
        // The PRF input names the hub, day and size as well as the root, so a
        // nonce can never be reused across peers or days to reproduce a sample.
        byte[] input = org.shalim.crypto.Canonical.of("shalim.replay.sample.v1")
                .hex(head.getHubKeyFingerprint()).date(head.getDay()).u64(head.getSize())
                .hex(head.getRootHash()).encode();
        List<Long> indices = org.shalim.crypto.Prf.sampleDistinct(dayNonce, input, sampleSize,
                head.getSize());
        java.util.Collections.sort(indices);
        return indices;
    }

    /**
     * Target side: checks a revealed day nonce against the anchor the auditor
     * committed to at link setup. Leaves are opened only if this holds.
     */
    public static boolean verifyRevealedNonce(byte[] anchor, LocalDate chainStart, LocalDate day,
                                              byte[] dayNonce) {
        return org.shalim.crypto.HashChain.verify(anchor, AuthLink.NONCE_CHAIN_DAYS, chainStart, day,
                dayNonce);
    }

    /**
     * Runs one day's replay against one peer. Returns an AuditRun of kind
     * REPLAY. Plaintext is decrypted, replayed and discarded inside this call.
     */
    public AuditRun replay(AuthLink link, CensorDecisionLog.SignedTreeHead head,
                           List<CensorDecisionLog.Opening> openings, byte[] dayNonce,
                           int expectedSampleSize, Instant now) {
        // PSEUDO-CODE
        //
        // 1. PRECONDITIONS
        //    IF NOT localCensor.isVerified() -> RETURN run VOID
        //       // A replay against an unverified local censor measures nothing.
        //    expected = sampleIndices(head, dayNonce, expectedSampleSize)
        //    IF openings missing any expected index -> anomaly(OPENING_WITHHELD, PEER)
        //
        // 2. FOR EACH opening
        //    IF NOT opening.proof.verify(opening.leaf.leafHash, head.rootHash)
        //       -> anomaly(OPENING_WITHHELD, PEER); continue
        //    IF opening.leaf.isPad()
        //       IF H("pad" || padValue) != leafHash -> anomaly(OPENING_WITHHELD, PEER)
        //       continue   // pads are not scored and not redrawn
        //    IF surface == MEETING_REQUEST AND NOT policy.replayMeetingRequests
        //       -> the peer should not have opened it; skip unread
        //    text = decrypt(opening.encryptedText, own key)
        //    IF sha256(text) != leaf.textHash -> anomaly(OPENING_WITHHELD, PEER)
        //    mine = localCensor.assess(text, leaf.surface)
        //    text = null   // never displayed, never stored, never logged
        //
        // 3. COMPARE
        //    IF |leaf.confidence - threshold| < CONFIDENCE_TOLERANCE for the
        //       surface's review or block threshold -> record UNDETERMINED; continue
        //    mismatch = mine.decision != leaf.decision
        //            OR mine.categories != leaf.categories
        //            OR |mine.confidence - leaf.confidence| > CONFIDENCE_TOLERANCE
        //            OR actionTaken does not follow from leaf.decision
        //    ledger.recordReplay(link.subject, head, leaf, mine, mismatch)
        //    IF mismatch -> anomaly(REPLAY_MISMATCH, PEER)
        //
        // 4. LOCAL FAULT CHECK
        //    IF leaf.censorPinHash != localCensor.pin().artefactHash
        //       -> the two hubs are on different releases; mark run VOID, not FAILED
        //
        // 5. RETURN run (kind REPLAY)
        return null;
    }

    /**
     * Checks a member receipt that the prober's device forwarded (see
     * {@link OrganicProbe}) against the head this auditor holds. A receipt
     * that does not verify against our head means the peer showed us a
     * different tree from the one it served its members.
     */
    public AuditAnomaly checkReceipt(String peerKeyFingerprint, CensorDecisionLog.Receipt receipt,
                                     CensorDecisionLog.InclusionProof proof) {
        // PSEUDO-CODE
        // head = stored head for (peer, receipt.day)
        // IF head absent -> RETURN null   // not synced yet; retry later
        // IF NOT proof.verify(receipt.leafHash, head.rootHash)
        //    RETURN anomaly(UNLOGGED_DECISION, PEER)
        //    // Either the screening was never logged, or the tree we hold is
        //    // not the one the member's leaf went into. Both are conclusive
        //    // once the hub's own signature on the receipt verifies.
        // RETURN null
        return null;
    }

    public String getOwnerKeyFingerprint() {
        return ownerKeyFingerprint;
    }

    public ProbeLedger getLedger() {
        return ledger;
    }

    /**
     * The day's nonce, revealed only after the head for {@code day} is signed.
     * Null if this side holds no chain seed (it is the target) or the chain has
     * run out, in which case the link must re-anchor.
     */
    public byte[] revealNonce(AuthLink link, LocalDate day) {
        byte[] seed = link.nonceSecret();
        LocalDate start = link.nonceChainStart();
        if (seed == null || start == null) {
            return null;
        }
        return org.shalim.crypto.HashChain.reveal(seed, AuthLink.NONCE_CHAIN_DAYS, start, day);
    }
}
