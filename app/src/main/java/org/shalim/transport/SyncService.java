package org.shalim.transport;

import java.util.List;
import org.shalim.hub.Hub;

/**
 * Keeps hub replicas converged across whatever transports are up.
 *
 * <p>Chooses a transport per job rather than per session: a full skills-layer
 * sync needs Wi-Fi or cellular, whereas LoRa can only carry a heartbeat and a
 * log head hash. Falling back from Wi-Fi to LoRa therefore means doing
 * <em>less</em>, not the same thing slower.
 */
public class SyncService {

    /** Ordered by preference; the service picks the best one that can carry the job. */
    private List<Transport> transports;

    private String hubId;

    /** What a given sync job needs from a transport. */
    public enum Job {
        /** "I exist, here's my log head." Fits on LoRa. */
        HEARTBEAT,
        /** A single short meeting request. Fits on LoRa. */
        MEETING_REQUEST,
        /**
         * Public discovery cards. Small enough for Bluetooth mesh, and
         * deliberately gossiped rather than fetched: a card requested on demand
         * would tell its hub that someone nearby was looking for it.
         */
        CARD_GOSSIP,
        /** Recent log entries. Needs Bluetooth mesh or better. */
        LOG_DELTA,
        /** Full skills layer and summaries. Needs Wi-Fi or cellular. */
        FULL_SYNC,
        /** Model artefact download. Wi-Fi only; hundreds of megabytes. */
        MODEL_FETCH
    }

    public SyncService() {
        // TODO: pseudo-code
    }

    public SyncService(String hubId, List<Transport> transports) {
        // TODO: pseudo-code
    }

    // --- transport selection ----------------------------------------------

    /** Best available transport that can actually carry the job, if any. */
    public Transport selectTransport(Job job) {
        // TODO: pseudo-code
        return null;
    }

    public boolean canPerform(Job job) {
        // TODO: pseudo-code
        return false;
    }

    // --- syncing ----------------------------------------------------------

    /** Exchanges log entries with one peer and merges what comes back. */
    public SyncOutcome syncWith(PeerEndpoint peer, Hub localHub, Job job) {
        // TODO: pseudo-code
        return null;
    }

    /** Opportunistic sync with every reachable peer. */
    public List<SyncOutcome> syncAll(Hub localHub) {
        // TODO: pseudo-code
        return null;
    }

    /** Periodic presence beacon; the only thing worth spending LoRa airtime on. */
    public boolean beacon(Hub localHub) {
        // TODO: pseudo-code
        return false;
    }

    // --- guest presence ---------------------------------------------------

    /**
     * Confirms a guest is on the hub's verified network. Guest access is scoped
     * to physical presence, so this must be re-checked, not cached indefinitely.
     */
    public boolean verifyPresence(String userId, Transport transport) {
        // TODO: pseudo-code
        return false;
    }

    /** Result of one peer exchange. */
    public static class SyncOutcome {
        private String peerEndpointId;
        private Job job;
        private boolean succeeded;
        private int entriesReceived;
        private int entriesSent;

        /** Set when the peer's censor pin did not match ours. */
        private boolean censorMismatch;

        private String failureReason;

        public boolean isSucceeded() {
            return succeeded;
        }

        public boolean hasCensorMismatch() {
            return censorMismatch;
        }

        public int getEntriesReceived() {
            return entriesReceived;
        }

        public String getFailureReason() {
            return failureReason;
        }
    }
}
