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
 * <p>The auditor commits to a nonce when the link is set up and reveals a
 * fresh one each day only after the peer's head is signed:
 * {@code indices = PRF(rootHash || nonce_day)}. The peer cannot predict the
 * sample when signing; the auditor cannot aim it at a particular leaf, and so
 * cannot use replay to read one member's question.
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
        // PSEUDO-CODE
        // prf = HMAC(dayNonce, head.rootHash)
        // draw sampleSize distinct indices in [0, head.size) from prf
        // RETURN indices
        return null;
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

    /** Placeholder for the day's nonce, revealed only after the head is signed. */
    public byte[] revealNonce(AuthLink link, LocalDate day) {
        // PSEUDO-CODE
        // RETURN HMAC(link.nonceSecret, day)
        //    // Commitment H(nonceSecret) was sent when the link was set up, so
        //    // the auditor cannot choose the nonce after seeing the root.
        return null;
    }
}
