package org.shalim.hub;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.shalim.crypto.Aead;
import org.shalim.crypto.Bytes;
import org.shalim.crypto.Canonical;
import org.shalim.crypto.CryptoException;
import org.shalim.crypto.Ed25519;
import org.shalim.crypto.EncryptionKeyPair;
import org.shalim.crypto.Fingerprints;
import org.shalim.crypto.Merkle;
import org.shalim.crypto.SealedBox;
import org.shalim.crypto.Signer;
import org.shalim.ml.CensorEngine;

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
 *       {@link #PAD_MULTIPLE} (minimum one block) with pad leaves, and signs
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
 * Nor does it hold keys: the hub's issuer {@link Signer} and its at-rest key
 * are passed to the methods that need them by the runtime.
 *
 * <h2>Exact encodings (implemented 29 October 2026)</h2>
 *
 * <p>All hashes are SHA-256 over {@link Canonical} encodings:
 * <ul>
 *   <li>text hash: {@code ("shalim.cdl.text.v1", leafSalt, text)}. Salted, so
 *       a seized hub device cannot confirm a guessed question against stored
 *       leaves.</li>
 *   <li>leaf hash: {@code ("shalim.cdl.leaf.v1", leafSalt, textHash, surface,
 *       decision, {categories}, confidence bits, actionTaken, censorPinHash,
 *       day)};</li>
 *   <li>pad hash: {@code ("shalim.cdl.pad.v1", r)}, r 32 random bytes;</li>
 *   <li>the tree: RFC 9162 over the leaf hashes ({@link Merkle});</li>
 *   <li>head, signed with Ed25519: {@code ("shalim.cdl.head.v1", hub key
 *       fingerprint, day, size, root, previousHeadHash, signedAt)};</li>
 *   <li>receipt, signed: {@code ("shalim.cdl.receipt.v1", hub key fingerprint,
 *       day, index, leafHash)};</li>
 *   <li>plaintext at rest: {@link Aead}, with associated data naming hub, day,
 *       index and leaf hash, so stored texts cannot be swapped between
 *       leaves;</li>
 *   <li>openings: {@link SealedBox} to the auditor's X25519 key, with
 *       associated data naming hub, auditor, day, index and leaf hash.</li>
 * </ul>
 *
 * <p>Days are UTC dates. Every day gets a head, including days with no
 * screenings, which pad to one full block. So a quiet day looks like a
 * light one, and the chain of heads has no gaps.
 */
public class CensorDecisionLog {

    /** Tree size is padded to a multiple of this before the head is signed. */
    public static final int PAD_MULTIPLE = 32;

    /** One committed screening. */
    public static final class Leaf {
        private final long index;
        private final String leafHash;
        /** Random per leaf; stops anyone confirming a guessed text against a leaf hash. */
        private final byte[] leafSalt;
        private final String textHash;
        private final CensorEngine.Surface surface;
        private final CensorEngine.Decision decision;
        private final List<CensorEngine.Category> categories;
        private final float confidence;
        /** What the hub actually did: answered, refused, held. Must follow from decision. */
        private final String actionTaken;
        private final String censorPinHash;
        private final LocalDate day;
        private final boolean pad;

        private Leaf(long index, byte[] leafSalt, String textHash, CensorEngine.Surface surface,
                     CensorEngine.Decision decision, List<CensorEngine.Category> categories,
                     float confidence, String actionTaken, String censorPinHash, LocalDate day,
                     boolean pad, String leafHash) {
            this.index = index;
            this.leafSalt = leafSalt == null ? null : leafSalt.clone();
            this.textHash = textHash;
            this.surface = surface;
            this.decision = decision;
            this.categories = categories == null ? List.of() : List.copyOf(categories);
            this.confidence = confidence;
            this.actionTaken = actionTaken;
            this.censorPinHash = censorPinHash;
            this.day = day;
            this.pad = pad;
            this.leafHash = leafHash;
        }

        static Leaf real(long index, String text, org.shalim.ml.Verdict verdict,
                         CensorEngine.Surface surface, String actionTaken, LocalDate day) {
            byte[] salt = Bytes.random(32);
            String textHash = textHash(salt, text);
            String hash = computeHash(salt, textHash, surface, verdict.getDecision(),
                    verdict.getCategories(), verdict.getConfidence(), actionTaken,
                    verdict.getModelPinHash(), day);
            return new Leaf(index, salt, textHash, surface, verdict.getDecision(),
                    verdict.getCategories(), verdict.getConfidence(), actionTaken,
                    verdict.getModelPinHash(), day, false, hash);
        }

        static Leaf pad(long index, byte[] padValue, LocalDate day) {
            return new Leaf(index, null, null, null, null, null, 0f, null, null, day, true,
                    padHash(padValue));
        }

        /** A leaf as an auditor receives it in an {@link Opening}. Check with {@link #hashMatches()}. */
        public static Leaf received(long index, byte[] leafSalt, String textHash,
                                    CensorEngine.Surface surface, CensorEngine.Decision decision,
                                    List<CensorEngine.Category> categories, float confidence,
                                    String actionTaken, String censorPinHash, LocalDate day,
                                    boolean pad, String leafHash) {
            return new Leaf(index, leafSalt, textHash, surface, decision, categories, confidence,
                    actionTaken, censorPinHash, day, pad, leafHash);
        }

        static String textHash(byte[] salt, String text) {
            return Canonical.of("shalim.cdl.text.v1").bytes(salt).string(text).digestHex();
        }

        static String padHash(byte[] padValue) {
            return Canonical.of("shalim.cdl.pad.v1").bytes(padValue).digestHex();
        }

        static String computeHash(byte[] salt, String textHash, CensorEngine.Surface surface,
                                  CensorEngine.Decision decision,
                                  List<CensorEngine.Category> categories, float confidence,
                                  String actionTaken, String censorPinHash, LocalDate day) {
            return Canonical.of("shalim.cdl.leaf.v1")
                    .bytes(salt).hex(textHash).enumName(surface).enumName(decision)
                    .enumSet(categories).f32(confidence).string(actionTaken)
                    .hex(censorPinHash).date(day)
                    .digestHex();
        }

        /**
         * Whether the decision fields shown are the ones the leaf hash commits
         * to. An auditor must check this before comparing decisions: the
         * inclusion proof covers only the hash. For a pad leaf, see
         * {@link Opening#padMatches()}.
         */
        public boolean hashMatches() {
            if (pad) {
                return false;
            }
            return Bytes.equalHex(leafHash, computeHash(leafSalt, textHash, surface, decision,
                    categories, confidence, actionTaken, censorPinHash, day));
        }

        /** Whether {@code text} is the text this leaf committed to. */
        public boolean textMatches(String text) {
            return !pad && text != null && Bytes.equalHex(textHash, textHash(leafSalt, text));
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

        public byte[] getLeafSalt() {
            return leafSalt == null ? null : leafSalt.clone();
        }

        public String getTextHash() {
            return textHash;
        }

        public CensorEngine.Surface getSurface() {
            return surface;
        }

        public CensorEngine.Decision getDecision() {
            return decision;
        }

        public List<CensorEngine.Category> getCategories() {
            return categories;
        }

        public float getConfidence() {
            return confidence;
        }

        public String getActionTaken() {
            return actionTaken;
        }

        public String getCensorPinHash() {
            return censorPinHash;
        }

        public LocalDate getDay() {
            return day;
        }
    }

    /** The hub's signed commitment to one day's tree. */
    public static final class SignedTreeHead {
        private final String hubKeyFingerprint;
        private final LocalDate day;
        /** Padded size. Real traffic lies between size - PAD_MULTIPLE and size. */
        private final long size;
        private final String rootHash;
        /** Hash of the previous day's head, so days form a chain and none can be dropped. */
        private final String previousHeadHash;
        private final String signature;
        private final Instant signedAt;

        private SignedTreeHead(String hubKeyFingerprint, LocalDate day, long size, String rootHash,
                               String previousHeadHash, Instant signedAt, String signature) {
            this.hubKeyFingerprint = hubKeyFingerprint;
            this.day = day;
            this.size = size;
            this.rootHash = rootHash;
            this.previousHeadHash = previousHeadHash;
            this.signedAt = signedAt;
            this.signature = signature;
        }

        static SignedTreeHead sign(Signer hubKey, LocalDate day, long size, String rootHash,
                                   String previousHeadHash, Instant now) {
            byte[] payload = payload(hubKey.fingerprint(), day, size, rootHash, previousHeadHash, now);
            return new SignedTreeHead(hubKey.fingerprint(), day, size, rootHash, previousHeadHash,
                    now, hubKey.signHex(payload));
        }

        /** A head as received over sync. Check with {@link #verify}. */
        public static SignedTreeHead received(String hubKeyFingerprint, LocalDate day, long size,
                                              String rootHash, String previousHeadHash,
                                              Instant signedAt, String signature) {
            return new SignedTreeHead(hubKeyFingerprint, day, size, rootHash, previousHeadHash,
                    signedAt, signature);
        }

        private static byte[] payload(String fp, LocalDate day, long size, String root,
                                      String previous, Instant signedAt) {
            return Canonical.of("shalim.cdl.head.v1").hex(fp).date(day).u64(size).hex(root)
                    .hex(previous).instant(signedAt).encode();
        }

        public boolean verify(byte[] hubPublicKey) {
            return Fingerprints.matchesSigningKey(hubKeyFingerprint, hubPublicKey)
                    && size % PAD_MULTIPLE == 0 && size > 0
                    && Ed25519.verifyHex(hubPublicKey,
                            payload(hubKeyFingerprint, day, size, rootHash, previousHeadHash, signedAt),
                            signature);
        }

        /** What the next day's head names as its predecessor. */
        public String headHash() {
            return Canonical.of("shalim.cdl.headhash.v1")
                    .bytes(payload(hubKeyFingerprint, day, size, rootHash, previousHeadHash, signedAt))
                    .digestHex();
        }

        /**
         * Coarse traffic band derived from the padded size. What
         * {@code AuditSchedule} uses to set the synthetic probe rate and to
         * decide whether the hub is too quiet for behavioural probing at all.
         */
        public int trafficBand() {
            return (int) (size / PAD_MULTIPLE);
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

        public String getSignature() {
            return signature;
        }

        public Instant getSignedAt() {
            return signedAt;
        }
    }

    /**
     * Handed to the member whose text was screened. Kept on their device only,
     * for the same fortnight, and used only by that device.
     */
    public static final class Receipt {
        private final LocalDate day;
        private final long leafIndex;
        private final String leafHash;
        private final byte[] leafSalt;
        /** Hub's signature over (hub, day, leafIndex, leafHash). Binds the hub to this leaf. */
        private final String hubSignature;

        private Receipt(LocalDate day, long leafIndex, String leafHash, byte[] leafSalt,
                        String hubSignature) {
            this.day = day;
            this.leafIndex = leafIndex;
            this.leafHash = leafHash;
            this.leafSalt = leafSalt.clone();
            this.hubSignature = hubSignature;
        }

        static Receipt sign(Signer hubKey, Leaf leaf) {
            byte[] payload = payload(hubKey.fingerprint(), leaf.day, leaf.index, leaf.leafHash);
            return new Receipt(leaf.day, leaf.index, leaf.leafHash, leaf.leafSalt,
                    hubKey.signHex(payload));
        }

        private static byte[] payload(String hubFp, LocalDate day, long index, String leafHash) {
            return Canonical.of("shalim.cdl.receipt.v1").hex(hubFp).date(day).u64(index)
                    .hex(leafHash).encode();
        }

        /**
         * Whether the hub really issued this receipt. Once this holds, a missing
         * leaf is the hub's fault and cannot be blamed on the member.
         */
        public boolean verify(byte[] hubPublicKey) {
            return hubPublicKey != null && Ed25519.verifyHex(hubPublicKey,
                    payload(Fingerprints.signingKey(hubPublicKey), day, leafIndex, leafHash), hubSignature);
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
            return leafSalt.clone();
        }

        public String getHubSignature() {
            return hubSignature;
        }
    }

    /** Merkle path from one leaf to a signed root. */
    public static final class InclusionProof {
        private final long leafIndex;
        private final long treeSize;
        private final List<String> path;

        public InclusionProof(long leafIndex, long treeSize, List<String> path) {
            this.leafIndex = leafIndex;
            this.treeSize = treeSize;
            this.path = List.copyOf(path);
        }

        public boolean verify(String leafHash, String rootHash) {
            try {
                List<byte[]> nodes = new ArrayList<>(path.size());
                for (String node : path) {
                    nodes.add(Bytes.fromHex(node));
                }
                return Merkle.verifyInclusion(Bytes.fromHex(leafHash), leafIndex, treeSize, nodes,
                        Bytes.fromHex(rootHash));
            } catch (IllegalArgumentException | NullPointerException malformed) {
                return false;
            }
        }

        public long getLeafIndex() {
            return leafIndex;
        }

        public long getTreeSize() {
            return treeSize;
        }

        public List<String> getPath() {
            return path;
        }
    }

    /**
     * What an auditor receives for one sampled index: the leaf, its inclusion
     * proof, and — for a real leaf — the plaintext, encrypted to the auditing
     * hub's key only. A pad leaf opens to its pad value instead. A
     * meeting-request leaf opened without the hub's consent to replay them
     * carries neither: its inclusion can be checked, its text cannot be read.
     */
    public static final class Opening {
        private final Leaf leaf;
        private final InclusionProof proof;
        private final byte[] encryptedText;
        private final byte[] padValue;

        public Opening(Leaf leaf, InclusionProof proof, byte[] encryptedText, byte[] padValue) {
            this.leaf = leaf;
            this.proof = proof;
            this.encryptedText = encryptedText == null ? null : encryptedText.clone();
            this.padValue = padValue == null ? null : padValue.clone();
        }

        /** For a pad leaf: whether the pad value opens to the leaf hash. */
        public boolean padMatches() {
            return leaf.pad && padValue != null && Bytes.equalHex(leaf.leafHash, Leaf.padHash(padValue));
        }

        /**
         * Decrypts the text on the auditing hub and checks it against the leaf.
         * Returns null if it does not decrypt or does not match. Either way the
         * opening counts as withheld. The caller must replay the text and
         * discard it in the same call; it is never stored.
         */
        public String openText(EncryptionKeyPair auditorKeys, String hubKeyFingerprint) {
            if (leaf.pad || encryptedText == null) {
                return null;
            }
            try {
                byte[] plain = SealedBox.open(auditorKeys, encryptedText,
                        openingAad(hubKeyFingerprint, auditorKeys.fingerprint(), leaf.day, leaf.index,
                                leaf.leafHash));
                String text = new String(plain, StandardCharsets.UTF_8);
                Bytes.wipe(plain);
                return leaf.textMatches(text) ? text : null;
            } catch (CryptoException e) {
                return null;
            }
        }

        public Leaf getLeaf() {
            return leaf;
        }

        public InclusionProof getProof() {
            return proof;
        }

        public byte[] getEncryptedText() {
            return encryptedText == null ? null : encryptedText.clone();
        }

        public byte[] getPadValue() {
            return padValue == null ? null : padValue.clone();
        }
    }

    private String hubKeyFingerprint;
    private LocalDate openDay;
    private List<Leaf> openLeaves;
    private List<SignedTreeHead> heads;

    /** Closed days' leaves, kept for the retention window so they can be opened. */
    private final Map<LocalDate, List<Leaf>> closedLeaves = new TreeMap<>();
    /** Plaintext sealed with the hub's at-rest key, by day then index. */
    private final Map<LocalDate, Map<Long, byte[]>> sealedTexts = new HashMap<>();
    /** Pad values, by day then index, so pads can be opened as pads. */
    private final Map<LocalDate, Map<Long, byte[]>> padValues = new HashMap<>();

    public CensorDecisionLog() {
        this.openLeaves = new ArrayList<>();
        this.heads = new ArrayList<>();
    }

    public CensorDecisionLog(String hubKeyFingerprint) {
        this();
        this.hubKeyFingerprint = hubKeyFingerprint;
    }

    // --- writing ----------------------------------------------------------

    /**
     * Commits one screening and returns the receipt for the asker. Called by
     * the censor gate for every screened text on a logged surface, before the
     * result is returned — so no answer leaves the hub without a leaf.
     *
     * <p>If the day has turned since the last screening, the previous day and
     * any empty days in between are closed first. A clock that has gone
     * backwards appends to the open day, because a closed day cannot change.
     *
     * @param hubKey     the hub issuer key; must be the key this log belongs to
     * @param atRestKey  the hub's 32-byte key for plaintext at rest
     */
    public synchronized Receipt append(String text, org.shalim.ml.Verdict verdict,
                                       CensorEngine.Surface surface, String actionTaken,
                                       Signer hubKey, byte[] atRestKey, Instant now) {
        requireOwnKey(hubKey);
        LocalDate today = utcDay(now);
        if (openDay == null) {
            openDay = lastHead() == null ? today : lastHead().day.plusDays(1);
        }
        while (openDay.isBefore(today)) {
            close(openDay, hubKey, now);
        }
        Leaf leaf = Leaf.real(openLeaves.size(), text, verdict, surface, actionTaken, openDay);
        openLeaves.add(leaf);
        byte[] plain = text.getBytes(StandardCharsets.UTF_8);
        sealedTexts.computeIfAbsent(openDay, d -> new HashMap<>()).put(leaf.index,
                Aead.seal(atRestKey, plain, atRestAad(leaf)));
        Bytes.wipe(plain);
        return Receipt.sign(hubKey, leaf);
    }

    /**
     * Ends a day: pads, builds the tree, signs the head. Heads are sent to
     * every hub with an inbound link during ordinary sync. The runtime calls
     * this once a day even when nothing was screened, so every day has a head.
     * Closing a day that already has a head returns that head. Days can only
     * be closed in order.
     */
    public synchronized SignedTreeHead close(LocalDate day, Signer hubKey, Instant now) {
        requireOwnKey(hubKey);
        SignedTreeHead existing = headFor(day);
        if (existing != null) {
            return existing;
        }
        SignedTreeHead last = lastHead();
        if (last != null && !day.isAfter(last.day)) {
            throw new IllegalStateException("days close in order; " + day + " is not after " + last.day);
        }
        // Close every earlier day first, so the chain has no gaps and an open
        // day's leaves are never skipped over.
        LocalDate first = last != null ? last.day.plusDays(1)
                : (openDay != null && openDay.isBefore(day) ? openDay : day);
        for (LocalDate d = first; d.isBefore(day); d = d.plusDays(1)) {
            closeOne(d, hubKey, now);
        }
        return closeOne(day, hubKey, now);
    }

    private SignedTreeHead closeOne(LocalDate day, Signer hubKey, Instant now) {
        SignedTreeHead last = lastHead();
        List<Leaf> leaves = day.equals(openDay) ? openLeaves : new ArrayList<>();
        long padded = Math.max(PAD_MULTIPLE,
                ((leaves.size() + PAD_MULTIPLE - 1) / PAD_MULTIPLE) * (long) PAD_MULTIPLE);
        Map<Long, byte[]> pads = new HashMap<>();
        for (long i = leaves.size(); i < padded; i++) {
            byte[] r = Bytes.random(32);
            pads.put(i, r);
            leaves.add(Leaf.pad(i, r, day));
        }
        padValues.put(day, pads);
        String root = Bytes.hex(Merkle.root(leafHashBytes(leaves)));
        SignedTreeHead head = SignedTreeHead.sign(hubKey, day, padded, root,
                last == null ? null : last.headHash(), now);
        heads.add(head);
        closedLeaves.put(day, Collections.unmodifiableList(new ArrayList<>(leaves)));
        if (day.equals(openDay) || openDay == null || !openDay.isAfter(day)) {
            openLeaves = new ArrayList<>();
            openDay = day.plusDays(1);
        }
        // Caller logs CENSOR_LOG_COMMITTED (day, size) in the HubLog — never per-leaf detail.
        return head;
    }

    /**
     * Closes every day up to and including {@code day} that has no head yet.
     * The daily housekeeping call, so quiet days still get heads. A no-op if
     * {@code day} is already closed.
     */
    public synchronized SignedTreeHead closeThrough(LocalDate day, Signer hubKey, Instant now) {
        SignedTreeHead last = lastHead();
        if (last != null && !day.isAfter(last.day)) {
            return headFor(day);
        }
        return close(day, hubKey, now);
    }

    // --- reading ----------------------------------------------------------

    /**
     * Opens sampled indices for an auditor. The indices are not chosen by the
     * auditor: they are derived from the signed root and the auditor's
     * pre-committed nonce (see {@code ReplayAuditor.sampleIndices}), so the
     * hub cannot know in advance which leaves will be opened and the auditor
     * cannot aim at one member's query.
     *
     * <p>Checking that {@code indices} really is that sample is the caller's
     * job (the runtime, with {@code ReplayAuditor.sampleIndices} and
     * {@code HashChain.verify}). This method opens what it is given.
     *
     * @param auditorEncryptionKey   the auditing hub's raw X25519 key
     * @param includeMeetingRequests {@code HubPolicy.isReplayMeetingRequests()}
     */
    public synchronized List<Opening> open(LocalDate day, List<Long> indices,
                                           byte[] auditorEncryptionKey, byte[] atRestKey,
                                           boolean includeMeetingRequests) {
        List<Opening> out = new ArrayList<>();
        List<Leaf> leaves = closedLeaves.get(day);
        SignedTreeHead head = headFor(day);
        if (leaves == null || head == null) {
            return out;
        }
        List<byte[]> data = leafHashBytes(leaves);
        String auditorFp = Fingerprints.encryptionKey(auditorEncryptionKey);
        for (long index : indices) {
            if (index < 0 || index >= leaves.size()) {
                continue;
            }
            Leaf leaf = leaves.get((int) index);
            InclusionProof proof = proof(data, (int) index);
            if (leaf.pad) {
                out.add(new Opening(leaf, proof, null, padValues.get(day).get(index)));
                continue;
            }
            byte[] sealed = sealedTexts.getOrDefault(day, Map.of()).get(index);
            if (sealed == null || (leaf.surface == CensorEngine.Surface.MEETING_REQUEST
                    && !includeMeetingRequests)) {
                out.add(new Opening(leaf, proof, null, null));
                continue;
            }
            byte[] plain = Aead.open(atRestKey, sealed, atRestAad(leaf));
            byte[] toAuditor = SealedBox.seal(auditorEncryptionKey, plain,
                    openingAad(hubKeyFingerprint, auditorFp, day, index, leaf.leafHash));
            Bytes.wipe(plain);
            out.add(new Opening(leaf, proof, toAuditor, null));
        }
        // Caller logs REPLAY_SAMPLE_OPENED (auditor key fingerprint, day, count).
        //    // Count only. Which indices were opened is not logged: the log is
        //    // itself seizable, and indices join to texts.
        return out;
    }

    /** Proof that a member's receipt is in the tree the auditors were shown. Null until the day closes. */
    public synchronized InclusionProof proveInclusion(LocalDate day, long leafIndex) {
        List<Leaf> leaves = closedLeaves.get(day);
        if (leaves == null || leafIndex < 0 || leafIndex >= leaves.size()) {
            return null;
        }
        return proof(leafHashBytes(leaves), (int) leafIndex);
    }

    public synchronized SignedTreeHead headFor(LocalDate day) {
        for (SignedTreeHead head : heads) {
            if (head.day.equals(day)) {
                return head;
            }
        }
        return null;
    }

    // --- retention --------------------------------------------------------

    /** Drops leaves, texts and pad values past the meeting-request window. Heads are kept. */
    public synchronized int prune(HubPolicy policy, Instant now) {
        return prune(policy.getMeetingRequestRetentionDays(), now);
    }

    /** As {@link #prune(HubPolicy, Instant)}, with the window given directly. Returns leaves dropped. */
    public synchronized int prune(int retentionDays, Instant now) {
        LocalDate cutoff = utcDay(now).minusDays(retentionDays);
        int dropped = 0;
        for (LocalDate day : new ArrayList<>(closedLeaves.keySet())) {
            if (day.isBefore(cutoff)) {
                dropped += closedLeaves.remove(day).size();
                wipeAll(sealedTexts.remove(day));
                wipeAll(padValues.remove(day));
            }
        }
        // KEEP signed heads (hashes and sizes only) so the chain still verifies
        return dropped;
    }

    /** Duress path, alongside HubLog.wipe. Heads go too. */
    public synchronized void wipe() {
        closedLeaves.clear();
        sealedTexts.values().forEach(CensorDecisionLog::wipeAll);
        sealedTexts.clear();
        padValues.values().forEach(CensorDecisionLog::wipeAll);
        padValues.clear();
        openLeaves = new ArrayList<>();
        openDay = null;
        heads = new ArrayList<>();
    }

    public synchronized List<SignedTreeHead> getHeads() {
        return Collections.unmodifiableList(new ArrayList<>(heads));
    }

    public String getHubKeyFingerprint() {
        return hubKeyFingerprint;
    }

    /**
     * Everything this log holds, for persistence. Texts stay sealed under the
     * at-rest key: the store never sees plaintext.
     */
    public record State(String hubKeyFingerprint, LocalDate openDay, List<Leaf> openLeaves, List<SignedTreeHead> heads,
                        Map<LocalDate, List<Leaf>> closedLeaves, Map<LocalDate, Map<Long, byte[]>> sealedTexts,
                        Map<LocalDate, Map<Long, byte[]>> padValues) {
    }

    public synchronized State exportState() {
        Map<LocalDate, List<Leaf>> closed = new TreeMap<>(closedLeaves);
        Map<LocalDate, Map<Long, byte[]>> texts = new TreeMap<>();
        sealedTexts.forEach((d, m) -> texts.put(d, new TreeMap<>(m)));
        Map<LocalDate, Map<Long, byte[]>> pads = new TreeMap<>();
        padValues.forEach((d, m) -> pads.put(d, new TreeMap<>(m)));
        return new State(hubKeyFingerprint, openDay, List.copyOf(openLeaves), List.copyOf(heads), closed, texts, pads);
    }

    /** Rebuilds a log from persisted state. The caller should then verify every head. */
    public static CensorDecisionLog restore(State s) {
        CensorDecisionLog log = new CensorDecisionLog(s.hubKeyFingerprint());
        log.openDay = s.openDay();
        log.openLeaves = new ArrayList<>(s.openLeaves());
        log.heads = new ArrayList<>(s.heads());
        s.closedLeaves().forEach((d, l) -> log.closedLeaves.put(d, Collections.unmodifiableList(new ArrayList<>(l))));
        s.sealedTexts().forEach((d, m) -> log.sealedTexts.put(d, new HashMap<>(m)));
        s.padValues().forEach((d, m) -> log.padValues.put(d, new HashMap<>(m)));
        return log;
    }

    // --- internals --------------------------------------------------------

    private void requireOwnKey(Signer hubKey) {
        if (hubKeyFingerprint == null) {
            hubKeyFingerprint = hubKey.fingerprint();
        } else if (!hubKeyFingerprint.equals(hubKey.fingerprint())) {
            throw new IllegalArgumentException("not this log's hub key");
        }
    }

    private SignedTreeHead lastHead() {
        return heads.isEmpty() ? null : heads.get(heads.size() - 1);
    }

    private static LocalDate utcDay(Instant now) {
        return LocalDate.ofInstant(now, ZoneOffset.UTC);
    }

    private static List<byte[]> leafHashBytes(List<Leaf> leaves) {
        List<byte[]> out = new ArrayList<>(leaves.size());
        for (Leaf leaf : leaves) {
            out.add(Bytes.fromHex(leaf.leafHash));
        }
        return out;
    }

    private static InclusionProof proof(List<byte[]> data, int index) {
        List<String> path = new ArrayList<>();
        for (byte[] node : Merkle.inclusionPath(data, index)) {
            path.add(Bytes.hex(node));
        }
        return new InclusionProof(index, data.size(), path);
    }

    private byte[] atRestAad(Leaf leaf) {
        return Canonical.of("shalim.cdl.text-at-rest.v1").hex(hubKeyFingerprint).date(leaf.day)
                .u64(leaf.index).hex(leaf.leafHash).encode();
    }

    static byte[] openingAad(String hubFp, String auditorFp, LocalDate day, long index, String leafHash) {
        return Canonical.of("shalim.cdl.opening.v1").hex(hubFp).hex(auditorFp).date(day).u64(index)
                .hex(leafHash).encode();
    }

    private static void wipeAll(Map<Long, byte[]> values) {
        if (values != null) {
            values.values().forEach(Bytes::wipe);
        }
    }
}
