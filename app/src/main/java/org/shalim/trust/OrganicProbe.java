package org.shalim.trust;

import java.time.Instant;
import org.shalim.hub.CensorDecisionLog;

/**
 * A probe that is a real question. Runs on the prober's own device, over
 * queries the prober was going to ask the peer hub anyway.
 *
 * <h2>Why</h2>
 *
 * <p>A synthetic probe can only hide in traffic, and a quiet hub has no
 * traffic to hide it in. An organic probe <em>is</em> the traffic, so it is
 * indistinguishable at any volume. The peer never learns a question was
 * checked, because nothing about the question changes: it goes through the
 * prober's ordinary membership, the ordinary query path and the ordinary rate
 * limit.
 *
 * <h2>What the device does</h2>
 * <ol>
 *   <li>Before sending, screens the text with its own copy of the pinned
 *       censor (every device already carries it) and keeps the verdict.</li>
 *   <li>Sends the query as normal and keeps the hub's
 *       {@link CensorDecisionLog.Receipt}.</li>
 *   <li>Compares the hub's visible behaviour — answered, refused, held, and
 *       the refusal wording — with its own verdict.</li>
 *   <li>Once the day's head is signed, asks the hub for an inclusion proof
 *       for its own receipt. Members ask for their own receipts routinely,
 *       so the request marks no one out.</li>
 *   <li>Forwards only the {@link DifferenceScore} and, if the receipt failed
 *       to verify, the receipt and proof, to its own hub's ledger. Never the
 *       text.</li>
 * </ol>
 *
 * <h2>What it cannot do</h2>
 *
 * <p>Test under-blocking. A prober does not ask for drugs, so organic traffic
 * almost never exercises the block path. That is covered by
 * {@link ReplayAuditor}. Organic probing covers the two things replay cannot:
 * that the hub logs everything it screens, and that it treats real members the
 * way its log says it does.
 *
 * <h2>Evidential weight</h2>
 *
 * <p>Organic scores are corroborating only, except for an unlogged receipt,
 * which is conclusive once the hub's signature on it verifies. The text is
 * the prober's own private question; it is never retained, so it cannot be
 * produced at an appeal, so it cannot carry a revocation by itself.
 */
public class OrganicProbe {

    private String probeId;
    private String peerKeyFingerprint;

    /** Hash of the prober's own text. The text itself is never kept. */
    private String textHash;

    private org.shalim.ml.CensorEngine.Surface surface;

    /** The device's own pinned verdict, taken before sending. */
    private org.shalim.ml.Verdict localVerdict;

    /** What the hub visibly did, as a ProbeOutcome. */
    private ProbeOutcome peerOutcome;

    private CensorDecisionLog.Receipt receipt;

    private boolean inclusionChecked;
    private boolean inclusionVerified;

    private Instant sentAt;

    /** The hub answered a logged surface without committing a leaf. Conclusive once signed. */
    private boolean answeredWithoutReceipt;

    /** Set by {@link #toScore}; everything else is dropped by {@link #forget}. */
    private DifferenceScore score;

    public OrganicProbe() {
        this.probeId = org.shalim.crypto.Bytes.randomId();
    }

    /**
     * Called by the client just before an ordinary query leaves the device, if
     * this account is a registered prober for the target hub and the schedule
     * says organic probing is on. Otherwise nothing happens and nothing is kept.
     */
    public static OrganicProbe shadow(String text, org.shalim.ml.CensorEngine.Surface surface,
                                      org.shalim.ml.CensorEngine deviceCensor,
                                      String peerKeyFingerprint, Instant now) {
        if (deviceCensor == null || !deviceCensor.isVerified() || text == null) {
            // An unverified local copy would make the prober's device the
            // outlier; skipping is better than scoring against it.
            return null;
        }
        OrganicProbe p = new OrganicProbe();
        p.peerKeyFingerprint = peerKeyFingerprint;
        p.textHash = org.shalim.crypto.Hashing.sha256Hex(text);
        p.surface = surface;
        p.localVerdict = deviceCensor.assess(text, surface);
        p.sentAt = now;
        return p;
    }

    /** Records what came back. */
    public void observe(org.shalim.query.QueryResult result, Instant now) {
        peerOutcome = ProbeOutcome.fromQueryResult(probeId, peerKeyFingerprint, result, now);
        receipt = result == null ? null : result.getCensorReceipt();
        // A screened answer, hold or refusal must carry a receipt. One without
        // is the hub answering without committing.
        answeredWithoutReceipt = result != null && receipt == null && peerOutcome.isScoreable();
    }

    /**
     * Once the day is closed, checks the receipt against the hub's own tree
     * via the hub's inclusion proof, and hands the receipt and proof on to the
     * prober's own hub, which checks them against the head <em>it</em> was
     * shown ({@link ReplayAuditor#checkReceipt}). The two checks together
     * catch a missing leaf and a split view.
     */
    public boolean checkInclusion(CensorDecisionLog.InclusionProof proof,
                                  CensorDecisionLog.SignedTreeHead headFromPeer) {
        inclusionChecked = true;
        inclusionVerified = receipt != null && proof != null && headFromPeer != null
                && receipt.getDay().equals(headFromPeer.getDay())
                && proof.getLeafIndex() == receipt.getLeafIndex()
                && proof.verify(receipt.getLeafHash(), headFromPeer.getRootHash());
        return inclusionVerified;
    }

    /**
     * The score sent to the prober's own hub. Scored against the device's own
     * pinned verdict rather than a corpus seed, because there is no seed.
     */
    public DifferenceScore toScore(org.shalim.ml.ProbeEngine prober) {
        score = prober != null ? prober.scoreOrganic(localVerdict, peerOutcome)
                : ProbeScoring.scoreOrganic(probeId, localVerdict, peerOutcome);
        return score;
    }

    /** Drops everything but the score. Called once the score has been forwarded. */
    public void forget() {
        localVerdict = null;
        peerOutcome = null;
        textHash = null;
    }

    public boolean isAnsweredWithoutReceipt() {
        return answeredWithoutReceipt;
    }

    public DifferenceScore getScore() {
        return score;
    }

    public String getProbeId() {
        return probeId;
    }

    public String getPeerKeyFingerprint() {
        return peerKeyFingerprint;
    }

    public String getTextHash() {
        return textHash;
    }

    public org.shalim.ml.CensorEngine.Surface getSurface() {
        return surface;
    }

    public CensorDecisionLog.Receipt getReceipt() {
        return receipt;
    }

    public boolean isInclusionChecked() {
        return inclusionChecked;
    }

    public boolean isInclusionVerified() {
        return inclusionVerified;
    }

    public Instant getSentAt() {
        return sentAt;
    }
}
