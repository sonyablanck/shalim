package org.shalim.hub;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;
import org.shalim.crypto.Bytes;
import org.shalim.crypto.Canonical;
import org.shalim.crypto.Ed25519;
import org.shalim.crypto.Fingerprints;
import org.shalim.crypto.Signer;

/**
 * Append-only, hash-chained record of what happened in a hub. Doubles as the
 * replication journal: peers exchange entries they have not seen and replay
 * them to converge after a blackout.
 *
 * <p>The log is also a liability. A full membership and activity history on a
 * seized device is exactly what endangers people under a hostile state, so
 * retention is bounded by {@link HubPolicy} and {@link #prune} is expected to
 * run, not to be optional.
 *
 * <h2>Format</h2>
 *
 * <p>Each entry's hash is SHA-256 over the canonical encoding (see
 * {@link Canonical}) of {@code ("shalim.hublog.entry.v1", hubId, entryId,
 * type, actorUserId, subjectId, detail, occurredAt, previousHash,
 * signerKeyFingerprint)}. The signer signs that hash with Ed25519. The signer
 * is whoever holds the key at the point of writing, normally the hub issuer
 * key on the hub instance. Signing keys are passed in, never held, so the log
 * stays plain state.
 *
 * <p>Pruning drops the oldest entries and keeps the hash of the last one
 * dropped as {@link #getAnchorHash() the anchor}. The first surviving entry's
 * {@code previousHash} must equal it, so the chain still verifies end to end
 * over what remains.
 */
public class HubLog {

    private String hubId;
    private List<Entry> entries;

    /** Hash of the newest entry. Advertised during sync to detect divergence cheaply. */
    private String headHash;

    /** Hash of the last entry pruned away; what the oldest surviving entry chains to. Null if none. */
    private String anchorHash;

    public enum EventType {
        HUB_CREATED,
        MEMBER_ADMITTED,
        MEMBER_LEFT,
        MEMBER_REMOVED,
        ROLE_ASSIGNED,
        RESTRICTION_APPLIED,
        RESTRICTION_LIFTED,
        SKILL_ADDED,
        SKILL_REMOVED,
        RESOURCE_ADDED,
        SUMMARY_GENERATED,
        QUERY_RAISED,
        MEETING_REQUESTED,
        MEETING_ANSWERED,
        /** A moderator read the member roster or the meeting-request log. */
        ROSTER_VIEWED,
        /** A walk-in was admitted as a guest on the strength of network presence. */
        GUEST_ADMITTED_BY_PRESENCE,
        CENSOR_FLAG_RAISED,
        CENSOR_FLAG_UPHELD,
        CENSOR_FLAG_OVERRIDDEN,
        CENSOR_INTEGRITY_FAILED,
        HUB_FLAGGED_COMPROMISED,
        HUB_FLAG_CLEARED,
        POLICY_CHANGED,
        MODEL_PIN_CHANGED,
        /**
         * An audit run against one peer finished — a day's replay, a batch of
         * organic scores, or one synthetic probe. Records the peer's key
         * fingerprint and the verdict, never the peer's hub id. Detail lives
         * in the ProbeLedger, on the same retention as meeting requests.
         */
        PROBE_RUN_COMPLETED,
        /** An admin set up authentication of a peer (key fingerprint only). */
        AUTH_LINK_SET_UP,
        AUTH_LINK_ACTIVATED,
        AUTH_LINK_SUSPENDED,
        AUTH_LINK_REVOKED,
        AUTH_LINK_DORMANT,
        AUTH_BOND_FORMED,
        AUTH_BOND_LAPSED,
        NETWORK_CLAIMED,
        /** Another hub answered for this hub's access point. */
        NETWORK_CLAIM_DISPUTED,
        NETWORK_CLAIM_MIGRATED,
        /**
         * Target hub accepted an anonymous prober for another hub. Detail is
         * the auditing hub's key fingerprint and the link pseudonym; there is
         * no user id to record.
         */
        PROBER_ACCEPTED,
        /** Target hub refused a prober; detail is the ProberEligibility result. */
        PROBER_REFUSED,
        /** A prober stopped being eligible; the link stops counting. */
        AUTH_LINK_INELIGIBLE,
        /** A day's CensorDecisionLog tree was signed. Day and padded size only. */
        CENSOR_LOG_COMMITTED,
        /** Leaves were opened for an auditor. Auditor key and count; never which leaves. */
        REPLAY_SAMPLE_OPENED,
        /**
         * A member presented twice in one epoch with different challenges, and
         * their secret was recovered. The only event that names a prober, and
         * only one whose own client broke the protocol.
         */
        NULLIFIER_DOUBLE_SPENT,
        RECIPROCITY_INVITE_SENT,
        RECIPROCITY_INVITE_ACCEPTED,
        /** Standing moved between UNAUTHENTICATED, AUTHENTICATED and REVOKED. */
        HUB_STANDING_CHANGED,
        /** A member or guest logged use of a hub resource, pending verification. */
        RESOURCE_INTERACTION_RECORDED,
        /** An admin verified an interaction and a skill credential was issued. */
        SKILL_EARNED_VERIFIED,
        SKILL_EARNED_REJECTED,
        /** A member presented a skill credential earned elsewhere. No issuer recorded. */
        SKILL_CREDENTIAL_IMPORTED,
        HUB_SKILLS_DERIVED,
        SYNC_COMPLETED,
        LOG_PRUNED,
        HUB_EXPORTED
    }

    /** One immutable, signed record. */
    public static final class Entry {
        private final String entryId;
        private final EventType type;
        private final String actorUserId;
        private final String subjectId;

        /** Short structured detail. Never free-text personal content. */
        private final String detail;

        private final Instant occurredAt;
        private final String previousHash;
        private final String signerKeyFingerprint;
        private final String hash;
        private final String signature;

        private Entry(String entryId, EventType type, String actorUserId, String subjectId,
                      String detail, Instant occurredAt, String previousHash,
                      String signerKeyFingerprint, String hash, String signature) {
            this.entryId = entryId;
            this.type = type;
            this.actorUserId = actorUserId;
            this.subjectId = subjectId;
            this.detail = detail;
            this.occurredAt = occurredAt;
            this.previousHash = previousHash;
            this.signerKeyFingerprint = signerKeyFingerprint;
            this.hash = hash;
            this.signature = signature;
        }

        /** Rebuilds an entry received from a peer. Nothing is trusted until {@link HubLog#mergeEntries}. */
        public static Entry received(String entryId, EventType type, String actorUserId,
                                     String subjectId, String detail, Instant occurredAt,
                                     String previousHash, String signerKeyFingerprint,
                                     String hash, String signature) {
            return new Entry(entryId, type, actorUserId, subjectId, detail, occurredAt,
                    previousHash, signerKeyFingerprint, hash, signature);
        }

        static String computeHash(String hubId, String entryId, EventType type, String actorUserId,
                                  String subjectId, String detail, Instant occurredAt,
                                  String previousHash, String signerKeyFingerprint) {
            return Canonical.of("shalim.hublog.entry.v1")
                    .string(hubId).string(entryId).enumName(type).string(actorUserId)
                    .string(subjectId).string(detail).instant(occurredAt).hex(previousHash)
                    .hex(signerKeyFingerprint)
                    .digestHex();
        }

        /** Whether the stored hash matches the content, for a log of this hub. */
        boolean hashMatches(String hubId) {
            return hash != null && Bytes.equalHex(hash, computeHash(hubId, entryId, type, actorUserId,
                    subjectId, detail, occurredAt, previousHash, signerKeyFingerprint));
        }

        /**
         * Verifies the signature over the hash. Checks that the key is the one
         * the entry names as signer, but not the hash against the content:
         * that needs the hub id, so {@link HubLog#verifyChain} does it.
         */
        public boolean verify(byte[] signerPublicKey) {
            return hash != null
                    && Fingerprints.matchesSigningKey(signerKeyFingerprint, signerPublicKey)
                    && Ed25519.verifyHex(signerPublicKey, Bytes.fromHex(hash), signature);
        }

        public String getEntryId() {
            return entryId;
        }

        public EventType getType() {
            return type;
        }

        public String getActorUserId() {
            return actorUserId;
        }

        public String getSubjectId() {
            return subjectId;
        }

        public String getDetail() {
            return detail;
        }

        public Instant getOccurredAt() {
            return occurredAt;
        }

        public String getPreviousHash() {
            return previousHash;
        }

        public String getSignerKeyFingerprint() {
            return signerKeyFingerprint;
        }

        public String getHash() {
            return hash;
        }

        public String getSignature() {
            return signature;
        }
    }

    public HubLog() {
        this.entries = new ArrayList<>();
    }

    public HubLog(String hubId) {
        this();
        this.hubId = hubId;
    }

    // --- writing ----------------------------------------------------------

    /** Appends, chains and signs an entry. */
    public synchronized Entry append(EventType type, String actorUserId, String subjectId,
                                     String detail, Signer signer, Instant now) {
        String entryId = Bytes.randomId();
        String previous = headHash;
        String signerFp = signer.fingerprint();
        String hash = Entry.computeHash(hubId, entryId, type, actorUserId, subjectId, detail, now,
                previous, signerFp);
        String signature = signer.signHex(Bytes.fromHex(hash));
        Entry entry = new Entry(entryId, type, actorUserId, subjectId, detail, now, previous,
                signerFp, hash, signature);
        entries.add(entry);
        headHash = hash;
        return entry;
    }

    // --- reading ----------------------------------------------------------

    /** Entries at or after {@code when}. */
    public synchronized List<Entry> since(Instant when) {
        List<Entry> out = new ArrayList<>();
        for (Entry e : entries) {
            if (!e.occurredAt.isBefore(when)) {
                out.add(e);
            }
        }
        return out;
    }

    public synchronized List<Entry> byType(EventType type) {
        List<Entry> out = new ArrayList<>();
        for (Entry e : entries) {
            if (e.type == type) {
                out.add(e);
            }
        }
        return out;
    }

    public synchronized List<Entry> byActor(String userId) {
        List<Entry> out = new ArrayList<>();
        for (Entry e : entries) {
            if (userId != null && userId.equals(e.actorUserId)) {
                out.add(e);
            }
        }
        return out;
    }

    public synchronized List<Entry> getEntries() {
        return Collections.unmodifiableList(new ArrayList<>(entries));
    }

    // --- replication ------------------------------------------------------

    /**
     * Entries the peer's advertised head does not cover: everything after the
     * entry whose hash it advertised. If the peer's head is not one of ours,
     * because it is empty, behind our anchor, or on a different branch, every
     * retained entry is returned and the peer sorts it out.
     */
    public synchronized List<Entry> entriesMissingFrom(String peerHeadHash) {
        if (peerHeadHash != null) {
            if (peerHeadHash.equals(headHash)) {
                return new ArrayList<>();
            }
            for (int i = 0; i < entries.size(); i++) {
                if (peerHeadHash.equals(entries.get(i).hash)) {
                    return new ArrayList<>(entries.subList(i + 1, entries.size()));
                }
            }
        }
        return new ArrayList<>(entries);
    }

    /**
     * Merges peer entries that extend this log. Each must chain to the current
     * head, hash correctly and carry a valid signature from a key that
     * {@code publicKeyForSigner} recognises. Duplicates are skipped. The merge
     * stops at the first entry that fails any check. Returns how many were
     * added.
     *
     * <p>A peer whose history has forked from ours, so that its first new entry
     * chains to something other than our head, is not reconciled here. That
     * is a sync-policy decision (stage 2 in the build order), not a format
     * one.
     */
    public synchronized int mergeEntries(List<Entry> peerEntries,
                                         Function<String, byte[]> publicKeyForSigner) {
        int added = 0;
        for (Entry e : peerEntries) {
            if (containsHash(e.hash)) {
                continue;
            }
            String expectedPrevious = headHash != null ? headHash : anchorHash;
            boolean chains = expectedPrevious == null ? e.previousHash == null
                    : expectedPrevious.equals(e.previousHash);
            byte[] key = e.signerKeyFingerprint == null ? null : publicKeyForSigner.apply(e.signerKeyFingerprint);
            if (!chains || !e.hashMatches(hubId) || !e.verify(key)) {
                break;
            }
            entries.add(e);
            headHash = e.hash;
            added++;
        }
        return added;
    }

    /**
     * Structural check: every hash matches its content and every entry chains
     * to the one before, starting from the anchor. Signatures are not checked.
     * See {@link #verifyChain(Function)}.
     */
    public synchronized boolean verifyChain() {
        return verifyChain(null);
    }

    /** Structure plus signatures, with keys looked up by signer fingerprint. */
    public synchronized boolean verifyChain(Function<String, byte[]> publicKeyForSigner) {
        String previous = anchorHash;
        for (Entry e : entries) {
            boolean chains = previous == null ? e.previousHash == null : previous.equals(e.previousHash);
            if (!chains || !e.hashMatches(hubId)) {
                return false;
            }
            if (publicKeyForSigner != null && !e.verify(publicKeyForSigner.apply(e.signerKeyFingerprint))) {
                return false;
            }
            previous = e.hash;
        }
        return previous == null ? headHash == null : previous.equals(headHash);
    }

    private boolean containsHash(String hash) {
        for (Entry e : entries) {
            if (e.hash.equals(hash)) {
                return true;
            }
        }
        return false;
    }

    // --- retention --------------------------------------------------------

    /**
     * Drops entries past the policy's retention window, re-anchoring the chain
     * so verification still works over what remains. Only a prefix is dropped:
     * an old entry behind a newer one is kept until everything before it has
     * aged out, so the chain is never broken in the middle.
     */
    public synchronized int prune(HubPolicy policy, Instant now) {
        return prune(policy.getLogRetentionDays(), now);
    }

    /** As {@link #prune(HubPolicy, Instant)}, with the retention window given directly. */
    public synchronized int prune(int retentionDays, Instant now) {
        Instant cutoff = now.minus(java.time.Duration.ofDays(retentionDays));
        int dropped = 0;
        while (!entries.isEmpty() && entries.get(0).occurredAt.isBefore(cutoff)) {
            anchorHash = entries.remove(0).hash;
            dropped++;
        }
        return dropped;
    }

    /**
     * Irreversibly destroys local log state. For duress use. In memory this is
     * all it can do. Once logs persist (Room), wiping must also destroy the
     * at-rest key, since deleted rows survive in flash.
     */
    public synchronized void wipe() {
        entries.clear();
        headHash = null;
        anchorHash = null;
    }

    public String getHeadHash() {
        return headHash;
    }

    public String getAnchorHash() {
        return anchorHash;
    }

    public String getHubId() {
        return hubId;
    }
}
