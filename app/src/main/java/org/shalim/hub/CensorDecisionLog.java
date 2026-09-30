package org.shalim.hub;

import java.time.Instant;
import java.time.LocalDate;
import java.util.List;

/**
 * An append-only, Merkle-committed record of every decision this hub's censor
 * made, so that another hub can check the censor by <em>replaying</em> a
 * random sample through its own copy of the pinned artefact instead of sending
 * test questions.
 *
 * <h2>Why this replaced supply probes</h2>
 *
 * <p>The earlier design tested the censor by sending, every day, a request to
 * buy drugs or weapons that a correct censor should stop. Such a request is
 * conspicuous: in any hub it stands out, and in a quiet hub it is the only
 * thing that happens all day. It also forced the target hub to know which
 * member was the prober, so it did not restrict them for asking — and that
 * knowledge is exactly what a dishonest hub needs to answer probes correctly
 * and everyone else however it likes.
 *
 * <p>TinyCensor is pinned ({@link org.shalim.ml.ModelPin}) and deterministic on
 * its reference backend. Given the same input it must produce the same
 * decision, categories and confidence. So a hub that commits to its decisions
 * before it knows which will be checked can be audited on its <em>real</em>
 * traffic: a mismatch between what it logged and what the pinned model says is
 * proof the logged decision did not come from the pinned model. No harmful
 * text is ever sent to test it.
 *
 * <h2>Shape</h2>
 *
 * <ul>
 *   <li>One tree per day. Each leaf commits to one screening:
 *       {@code H(leafSalt || H(text) || surface || decision || categories ||
 *       confidence || actionTaken || censorPinHash || day)}. No member id, no
 *       query id that joins to the roster.</li>
 *   <li>At the end of the day the hub pads the tree to the next multiple of
 *       {@link #PAD_MULTIPLE} with pad leaves {@code H("pad" || r_i)}, and signs
 *       a {@link SignedTreeHead}. Padding stops the exact daily count becoming
 *       an activity signal to auditors.</li>
 *   <li>Every querying member is handed a {@link Receipt} for their own
 *       screening: the leaf, its index and the hub's signature over the
 *       pending head. That receipt is what later catches a hub that routes
 *       some traffic around the log, or shows different auditors different
 *       trees.</li>
 *   <li>Plaintext is held separately, encrypted at rest, on the same
 *       fortnight retention as meeting requests and Matchmaker queries. No
 *       new category of plaintext is retained: the texts were already kept for
 *       that long.</li>
 * </ul>
 *
 * <p>This is hub <em>state</em>. It is appended to by {@link QueryService}
 * and read by {@code org.shalim.trust.ReplayAuditor}; it holds no engine.
 */
public class CensorDecisionLog {

    /** Tree size is padded to a multiple of this before the head is signed. */
    public static final int PAD_MULTIPLE = 32;

    /** One committed screening. */
    public static class Leaf {
        private long index;
        private String leafHash;
        /** Random per leaf; stops anyone confirming a guessed text against a leaf hash. */
        private byte[] leafSalt;
        private String textHash;
        private org.shalim.ml.CensorEngine.Surface surface;
        private org.shalim.ml.CensorEngine.Decision decision;
        private List<org.shalim.ml.CensorEngine.Category> categories;
        private float confidence;
        /** What the hub actually did: answered, refused, held. Must follow from decision. */
        private String actionTaken;
        private String censorPinHash;
        private boolean pad;

        public Leaf() {
            // TODO: pseudo-code
        }

        public long getIndex() {
            return index;
        }

        public String getLeafHash() {
            return leafHash;
        }

        public boolean isPad() {
            return pad;
        }

        public org.shalim.ml.CensorEngine.Surface getSurface() {
            return surface;
        }

        public org.shalim.ml.CensorEngine.Decision getDecision() {
            return decision;
        }

        public float getConfidence() {
            return confidence;
        }

        public String getCensorPinHash() {
            return censorPinHash;
        }
    }

    /** The hub's signed commitment to one day's tree. */
    public static class SignedTreeHead {
        private String hubKeyFingerprint;
        private LocalDate day;
        /** Padded size. Real traffic lies between size - PAD_MULTIPLE and size. */
        private long size;
        private String rootHash;
        /** Hash of the previous day's head, so days form a chain and none can be dropped. */
        private String previousHeadHash;
        private String signature;
        private Instant signedAt;

        public SignedTreeHead() {
            // TODO: pseudo-code
        }

        public boolean verify(byte[] hubPublicKey) {
            // TODO: pseudo-code
            return false;
        }

        /**
         * Coarse traffic band derived from the padded size. What
         * {@code AuditSchedule} uses to set the synthetic probe rate and to
         * decide whether the hub is too quiet for behavioural probing at all.
         */
        public int trafficBand() {
            // PSEUDO-CODE
            // RETURN size / PAD_MULTIPLE
            return 0;
        }

        public LocalDate getDay() {
            return day;
        }

        public long getSize() {
            return size;
        }

        public String getRootHash() {
            return rootHash;
        }

        public String getHubKeyFingerprint() {
            return hubKeyFingerprint;
        }

        public String getPreviousHeadHash() {
            return previousHeadHash;
        }
    }

    /**
     * Handed to the member whose text was screened. Kept on their device only,
     * for the same fortnight, and used only by that device.
     */
    public static class Receipt {
        private LocalDate day;
        private long leafIndex;
        private String leafHash;
        private byte[] leafSalt;
        /** Hub's signature over (day, leafIndex, leafHash). Binds the hub to this leaf. */
        private String hubSignature;

        public Receipt() {
            // TODO: pseudo-code
        }

        public LocalDate getDay() {
            return day;
        }

        public long getLeafIndex() {
            return leafIndex;
        }

        public String getLeafHash() {
            return leafHash;
        }

        public byte[] getLeafSalt() {
            return leafSalt;
        }
    }

    /** Merkle path from one leaf to a signed root. */
    public static class InclusionProof {
        private long leafIndex;
        private long treeSize;
        private List<String> path;

        public InclusionProof() {
            // TODO: pseudo-code
        }

        public boolean verify(String leafHash, String rootHash) {
            // TODO: pseudo-code
            return false;
        }
    }

    /**
     * What an auditor receives for one sampled index: the leaf, its inclusion
     * proof, and — for a real leaf — the plaintext, encrypted to the auditing
     * hub's key only. A pad leaf opens to its pad value instead.
     */
    public static class Opening {
        private Leaf leaf;
        private InclusionProof proof;
        private byte[] encryptedText;
        private byte[] padValue;

        public Opening() {
            // TODO: pseudo-code
        }

        public Leaf getLeaf() {
            return leaf;
        }

        public InclusionProof getProof() {
            return proof;
        }

        public byte[] getEncryptedText() {
            return encryptedText;
        }

        public byte[] getPadValue() {
            return padValue;
        }
    }

    private String hubKeyFingerprint;
    private LocalDate openDay;
    private List<Leaf> openLeaves;
    private List<SignedTreeHead> heads;

    public CensorDecisionLog() {
        // TODO: pseudo-code
    }

    public CensorDecisionLog(String hubKeyFingerprint) {
        // TODO: pseudo-code
    }

    // --- writing ----------------------------------------------------------

    /**
     * Commits one screening and returns the receipt for the asker. Called by
     * the censor gate for every screened text on a logged surface, before the
     * result is returned — so no answer leaves the hub without a leaf.
     */
    public Receipt append(String text, org.shalim.ml.Verdict verdict,
                          org.shalim.ml.CensorEngine.Surface surface,
                          String actionTaken, Instant now) {
        // PSEUDO-CODE
        // IF day(now) != openDay -> close(openDay, now)
        // leaf = Leaf(index = openLeaves.size, salt = fresh random,
        //             textHash = sha256(text), surface, verdict fields,
        //             actionTaken, censorPinHash = verdict.modelPinHash)
        // leaf.leafHash = H(salt || textHash || ... || day)
        // openLeaves.add(leaf)
        // store encrypt_at_rest(text) keyed by (day, index), retention = fortnight
        // RETURN Receipt(day, index, leafHash, salt, sign(day || index || leafHash))
        return null;
    }

    /**
     * Ends a day: pads, builds the tree, signs the head. Heads are sent to
     * every hub with an inbound link during ordinary sync.
     */
    public SignedTreeHead close(LocalDate day, Instant now) {
        // PSEUDO-CODE
        // pad openLeaves to next multiple of PAD_MULTIPLE with pad leaves
        //    H("pad" || r_i), r_i fresh random, r_i kept for the fortnight
        // root = merkleRoot(openLeaves)
        // head = SignedTreeHead(day, size, root, previous = hash(last head))
        // sign head with the hub issuer key; heads.add(head)
        // log CENSOR_LOG_COMMITTED (day, size) — never per-leaf detail
        // RETURN head
        return null;
    }

    // --- reading ----------------------------------------------------------

    /**
     * Opens sampled indices for an auditor. The indices are not chosen by the
     * auditor: they are derived from the signed root and the auditor's
     * pre-committed nonce (see {@code ReplayAuditor.sampleIndices}), so the
     * hub cannot know in advance which leaves will be opened and the auditor
     * cannot aim at one member's query.
     */
    public List<Opening> open(LocalDate day, List<Long> indices, byte[] auditorPublicKey) {
        // PSEUDO-CODE
        // FOR EACH index
        //    IF leaf is pad -> Opening(leaf, proof, padValue = r_i)
        //    ELSE -> Opening(leaf, proof, encrypt(text, auditorPublicKey))
        // log REPLAY_SAMPLE_OPENED (auditor key fingerprint, day, count)
        //    // Count only. Which indices were opened is not logged: the log is
        //    // itself seizable, and indices join to texts.
        return null;
    }

    /** Proof that a member's receipt is in the tree the auditors were shown. */
    public InclusionProof proveInclusion(LocalDate day, long leafIndex) {
        // TODO: pseudo-code
        return null;
    }

    public SignedTreeHead headFor(LocalDate day) {
        // TODO: pseudo-code
        return null;
    }

    // --- retention --------------------------------------------------------

    /** Drops leaves, texts and pad values past the meeting-request window. Heads are kept. */
    public int prune(HubPolicy policy, Instant now) {
        // PSEUDO-CODE
        // cutoff = now - policy.meetingRequestRetentionDays
        // DROP leaves, encrypted texts, pad values for days < cutoff
        // KEEP signed heads (hashes and sizes only) so the chain still verifies
        return 0;
    }

    /** Duress path, alongside HubLog.wipe. */
    public void wipe() {
        // TODO: pseudo-code
    }

    public List<SignedTreeHead> getHeads() {
        return heads;
    }

    public String getHubKeyFingerprint() {
        return hubKeyFingerprint;
    }
}
