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

    /** Review and block thresholds the pinned censor applies. Leaves this close to one are not scored. */
    public static final float REVIEW_THRESHOLD = 0.5f;
    public static final float BLOCK_THRESHOLD = 0.9f;

    private String ownerKeyFingerprint;
    private org.shalim.ml.CensorEngine localCensor;
    private ProbeLedger ledger;

    /** This hub's encryption key: openings are sealed to it. */
    private org.shalim.crypto.EncryptionKeyPair encryptionKeys;

    /** Heads received, by peer key fingerprint then day. Kept so equivocation shows. */
    private final java.util.Map<String, java.util.TreeMap<LocalDate, CensorDecisionLog.SignedTreeHead>> heads =
            new java.util.HashMap<>();

    /** Equivocations seen while accepting heads, not yet folded into a run. */
    private final java.util.Map<String, List<AuditAnomaly>> pendingHeadFindings = new java.util.HashMap<>();

    public ReplayAuditor() {
    }

    public ReplayAuditor(String ownerKeyFingerprint, org.shalim.ml.CensorEngine localCensor,
                         ProbeLedger ledger, org.shalim.crypto.EncryptionKeyPair encryptionKeys) {
        this.ownerKeyFingerprint = ownerKeyFingerprint;
        this.localCensor = localCensor;
        this.ledger = ledger;
        this.encryptionKeys = encryptionKeys;
    }

    /**
     * Accepts a peer's head for a day, checking signature and chain. Keeps
     * every head so equivocation can be spotted when a receipt disagrees.
     */
    public synchronized boolean acceptHead(CensorDecisionLog.SignedTreeHead head, byte[] peerPublicKey) {
        if (head == null || peerPublicKey == null || !head.verify(peerPublicKey)) {
            return false;
        }
        String peer = head.getHubKeyFingerprint();
        java.util.TreeMap<LocalDate, CensorDecisionLog.SignedTreeHead> mine =
                heads.computeIfAbsent(peer, k -> new java.util.TreeMap<>());
        CensorDecisionLog.SignedTreeHead prior = mine.get(head.getDay());
        java.time.Instant now = head.getSignedAt();
        if (prior != null) {
            if (!org.shalim.crypto.Bytes.equalHex(prior.getRootHash(), head.getRootHash())
                    || prior.getSize() != head.getSize()) {
                pendingHeadFindings.computeIfAbsent(peer, k -> new java.util.ArrayList<>()).add(AuditAnomaly.of(
                        AuditAnomaly.Kind.EQUIVOCATION, AuditAnomaly.Attribution.PEER, null, head.getDay(),
                        "The hub signed two different records for " + head.getDay() + ".", now));
            }
            return true; // keep the first; the second is the evidence
        }
        CensorDecisionLog.SignedTreeHead before = mine.get(head.getDay().minusDays(1));
        if (before != null && !org.shalim.crypto.Bytes.equalHex(before.headHash(), head.getPreviousHeadHash())) {
            pendingHeadFindings.computeIfAbsent(peer, k -> new java.util.ArrayList<>()).add(AuditAnomaly.of(
                    AuditAnomaly.Kind.EQUIVOCATION, AuditAnomaly.Attribution.PEER, null, head.getDay(),
                    "The hub's record for " + head.getDay() + " does not follow on from the day before.", now));
        }
        CensorDecisionLog.SignedTreeHead after = mine.get(head.getDay().plusDays(1));
        if (after != null && !org.shalim.crypto.Bytes.equalHex(head.headHash(), after.getPreviousHeadHash())) {
            pendingHeadFindings.computeIfAbsent(peer, k -> new java.util.ArrayList<>()).add(AuditAnomaly.of(
                    AuditAnomaly.Kind.EQUIVOCATION, AuditAnomaly.Attribution.PEER, null, head.getDay(),
                    "The hub's record for " + head.getDay() + " does not lead to the day after.", now));
        }
        mine.put(head.getDay(), head);
        return true;
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
        String peer = link.getSubjectKeyFingerprint();
        AuditRun run = AuditRun.replay(peer, head.getDay(), expectedSampleSize, now);
        synchronized (this) {
            List<AuditAnomaly> pending = pendingHeadFindings.remove(peer);
            if (pending != null) {
                pending.forEach(run::addAnomaly);
            }
        }
        // 1. Preconditions. A replay against an unverified local censor measures nothing.
        if (localCensor == null || !localCensor.isVerified() || encryptionKeys == null) {
            run.markLocalUnverified();
            run.complete(now, null);
            return run;
        }
        CensorDecisionLog.SignedTreeHead held = headFor(peer, head.getDay());
        if (held == null || !org.shalim.crypto.Bytes.equalHex(held.getRootHash(), head.getRootHash())) {
            run.addAnomaly(AuditAnomaly.of(AuditAnomaly.Kind.EQUIVOCATION, AuditAnomaly.Attribution.PEER, null,
                    head.getDay(), "The openings were for a record this hub was not given.", now));
            run.complete(now, null);
            return run;
        }
        List<Long> expected = sampleIndices(head, dayNonce, expectedSampleSize);
        java.util.Map<Long, CensorDecisionLog.Opening> byIndex = new java.util.HashMap<>();
        for (CensorDecisionLog.Opening o : openings == null ? List.<CensorDecisionLog.Opening>of() : openings) {
            byIndex.putIfAbsent(o.getLeaf().getIndex(), o);
        }
        String localPin = localCensor.pin().getArtefactHash();
        for (long index : expected) {
            CensorDecisionLog.Opening o = byIndex.get(index);
            if (o == null) {
                run.addAnomaly(withheld(head.getDay(), "Sampled entry " + index + " was not opened.", now));
                continue;
            }
            CensorDecisionLog.Leaf leaf = o.getLeaf();
            // 2. Proof first: the inclusion proof covers only the hash.
            if (o.getProof() == null || o.getProof().getLeafIndex() != index
                    || !o.getProof().verify(leaf.getLeafHash(), head.getRootHash())) {
                run.addAnomaly(withheld(head.getDay(), "Entry " + index + " came with an invalid proof.", now));
                continue;
            }
            if (leaf.isPad()) {
                if (!o.padMatches()) {
                    run.addAnomaly(withheld(head.getDay(), "Padding entry " + index + " did not open as padding.",
                            now));
                } else {
                    run.countReplay(true, false, false);
                }
                continue;
            }
            if (!leaf.hashMatches()) {
                run.addAnomaly(withheld(head.getDay(), "Entry " + index + " does not match what was committed.",
                        now));
                continue;
            }
            // 4. Different releases on the two sides: not a finding about anyone.
            if (localPin == null || !org.shalim.crypto.Bytes.equalHex(localPin, leaf.getCensorPinHash())) {
                run.markPinMismatch();
                continue;
            }
            // Meeting requests are replayed at every hub (decided 19 November
            // 2026), so one opened without its text is withheld like any other.
            String text = o.openText(encryptionKeys, peer);
            if (text == null) {
                run.addAnomaly(withheld(head.getDay(), "Entry " + index + " could not be read.", now));
                continue;
            }
            org.shalim.ml.Verdict mine = localCensor.assess(text, leaf.getSurface());
            text = null; // never displayed, never stored, never logged
            // 3. Compare. Near a threshold, honest drift could flip the decision.
            if (nearThreshold(leaf.getConfidence()) || nearThreshold(mine.getConfidence())) {
                run.countReplay(false, true, false);
                ledger.recordReplay(peer, head, leaf, null, false, run.getRunId(), now);
                continue;
            }
            boolean mismatch = mine.getDecision() != leaf.getDecision()
                    || !new java.util.HashSet<>(mine.getCategories()).equals(new java.util.HashSet<>(leaf.getCategories()))
                    || Math.abs(mine.getConfidence() - leaf.getConfidence()) > CONFIDENCE_TOLERANCE
                    || !actionFollows(leaf.getDecision(), leaf.getActionTaken());
            run.countReplay(false, false, !mismatch);
            ledger.recordReplay(peer, head, leaf, mine, mismatch, run.getRunId(), now);
            if (mismatch) {
                run.addAnomaly(AuditAnomaly.of(AuditAnomaly.Kind.REPLAY_MISMATCH, AuditAnomaly.Attribution.PEER, null,
                        head.getDay(), "Entry " + index + ": the hub logged " + leaf.getDecision() + " and "
                                + leaf.getActionTaken() + "; the same model here says " + mine.getDecision() + ".",
                        now));
            }
        }
        run.complete(now, null);
        return run;
    }

    /**
     * Checks a member receipt that the prober's device forwarded (see
     * {@link OrganicProbe}) against the head this auditor holds. A receipt
     * that does not verify against our head means the peer showed us a
     * different tree from the one it served its members.
     */
    public AuditAnomaly checkReceipt(String peerKeyFingerprint, byte[] peerPublicKey,
                                     CensorDecisionLog.Receipt receipt, CensorDecisionLog.InclusionProof proof,
                                     java.time.Instant now) {
        if (receipt == null || peerPublicKey == null || !receipt.verify(peerPublicKey)) {
            return null; // not the hub's receipt; proves nothing about the hub
        }
        CensorDecisionLog.SignedTreeHead head = headFor(peerKeyFingerprint, receipt.getDay());
        if (head == null) {
            return null; // not synced yet; retry later
        }
        if (proof == null || proof.getLeafIndex() != receipt.getLeafIndex() || proof.getTreeSize() != head.getSize()
                || !proof.verify(receipt.getLeafHash(), head.getRootHash())) {
            // Either the screening was never logged, or the tree we hold is not
            // the one the member's leaf went into. Both are conclusive once the
            // hub's own signature on the receipt verifies, as it has.
            return AuditAnomaly.of(AuditAnomaly.Kind.UNLOGGED_DECISION, AuditAnomaly.Attribution.PEER, null,
                    receipt.getDay(), "A member's signed receipt is not in the record the hub showed this hub.", now);
        }
        return null;
    }

    /** A head held for (peer, day), or null. */
    public synchronized CensorDecisionLog.SignedTreeHead headFor(String peerKeyFingerprint, LocalDate day) {
        java.util.TreeMap<LocalDate, CensorDecisionLog.SignedTreeHead> m = heads.get(peerKeyFingerprint);
        return m == null ? null : m.get(day);
    }

    /** The latest head held for a peer, or null. */
    public synchronized CensorDecisionLog.SignedTreeHead latestHead(String peerKeyFingerprint) {
        java.util.TreeMap<LocalDate, CensorDecisionLog.SignedTreeHead> m = heads.get(peerKeyFingerprint);
        return m == null || m.isEmpty() ? null : m.lastEntry().getValue();
    }

    /** Drops heads older than retention. */
    public synchronized int pruneHeads(LocalDate cutoff) {
        int n = 0;
        for (java.util.TreeMap<LocalDate, CensorDecisionLog.SignedTreeHead> m : heads.values()) {
            java.util.Map<LocalDate, CensorDecisionLog.SignedTreeHead> old = m.headMap(cutoff);
            n += old.size();
            old.clear();
        }
        return n;
    }

    public synchronized void wipe() {
        heads.clear();
        pendingHeadFindings.clear();
    }

    /** What the action recorded must be for each decision. */
    static boolean actionFollows(org.shalim.ml.CensorEngine.Decision d, String action) {
        if (d == null || action == null) {
            return false;
        }
        return switch (d) {
            case BLOCK -> action.equals("refused");
            case REVIEW -> action.equals("held");
            case ALLOW -> action.equals("answered") || action.equals("delivered");
        };
    }

    static boolean nearThreshold(float confidence) {
        return Math.abs(confidence - REVIEW_THRESHOLD) < CONFIDENCE_TOLERANCE
                || Math.abs(confidence - BLOCK_THRESHOLD) < CONFIDENCE_TOLERANCE;
    }

    private static AuditAnomaly withheld(LocalDate day, String why, java.time.Instant now) {
        return AuditAnomaly.of(AuditAnomaly.Kind.OPENING_WITHHELD, AuditAnomaly.Attribution.PEER, null, day, why, now);
    }

    public org.shalim.crypto.EncryptionKeyPair encryptionKeys() {
        return encryptionKeys;
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
