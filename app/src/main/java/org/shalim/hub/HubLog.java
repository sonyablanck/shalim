package org.shalim.hub;

import java.time.Instant;
import java.util.List;

/**
 * Append-only, hash-chained record of what happened in a hub. Doubles as the
 * replication journal: peers exchange entries they have not seen and replay
 * them to converge after a blackout.
 *
 * <p>The log is also a liability. A full membership and activity history on a
 * seized device is exactly what endangers people under a hostile state, so
 * retention is bounded by {@link HubPolicy} and {@link #prune} is expected to
 * run, not to be optional.
 */
public class HubLog {

    private String hubId;
    private List<Entry> entries;

    /** Hash of the newest entry. Advertised during sync to detect divergence cheaply. */
    private String headHash;

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
    public static class Entry {
        private String entryId;
        private EventType type;
        private String actorUserId;
        private String subjectId;

        /** Short structured detail. Never free-text personal content. */
        private String detail;

        private Instant occurredAt;
        private String previousHash;
        private String hash;
        private String signature;

        public Entry() {
            // TODO: pseudo-code
        }

        public boolean verify(byte[] actorPublicKey) {
            // TODO: pseudo-code
            return false;
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

        public String getHash() {
            return hash;
        }
    }

    public HubLog() {
        // TODO: pseudo-code
    }

    public HubLog(String hubId) {
        // TODO: pseudo-code
    }

    // --- writing ----------------------------------------------------------

    /** Appends, chains and signs an entry. */
    public Entry append(EventType type, String actorUserId, String subjectId, String detail) {
        // TODO: pseudo-code
        return null;
    }

    // --- reading ----------------------------------------------------------

    public List<Entry> since(Instant when) {
        // TODO: pseudo-code
        return null;
    }

    public List<Entry> byType(EventType type) {
        // TODO: pseudo-code
        return null;
    }

    public List<Entry> byActor(String userId) {
        // TODO: pseudo-code
        return null;
    }

    // --- replication ------------------------------------------------------

    /** Entries the peer's advertised head does not cover. */
    public List<Entry> entriesMissingFrom(String peerHeadHash) {
        // TODO: pseudo-code
        return null;
    }

    /** Merges peer entries, dropping duplicates and rejecting bad signatures. */
    public int mergeEntries(List<Entry> peerEntries) {
        // TODO: pseudo-code
        return 0;
    }

    public boolean verifyChain() {
        // TODO: pseudo-code
        return false;
    }

    // --- retention --------------------------------------------------------

    /**
     * Drops entries past the policy's retention window, re-anchoring the chain
     * so verification still works over what remains.
     */
    public int prune(HubPolicy policy, Instant now) {
        // TODO: pseudo-code
        return 0;
    }

    /** Irreversibly destroys local log state. For duress use. */
    public void wipe() {
        // TODO: pseudo-code
    }

    public String getHeadHash() {
        return headHash;
    }

    public String getHubId() {
        return hubId;
    }
}
