package org.shalim.transport;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;
import org.shalim.crypto.Bytes;
import org.shalim.crypto.Signer;
import org.shalim.hub.ClaimAnswer;
import org.shalim.hub.Hub;
import org.shalim.hub.HubLog;
import org.shalim.hub.NetworkClaimService;

/**
 * Keeps hub replicas converged across whatever transports are up.
 *
 * <p>Chooses a transport per job rather than per session: a full skills-layer
 * sync needs Wi-Fi or cellular, whereas LoRa can only carry a heartbeat and a
 * log head hash. Falling back from Wi-Fi to LoRa therefore means doing
 * <em>less</em>, not the same thing slower.
 *
 * <h2>What it does (implemented in stage 2)</h2>
 * <ul>
 *   <li>Answers on every transport it is given: {@link SecureChannel}
 *       handshakes as responder, sealed sync messages, claim queries (when it
 *       is a hub instance with a claim), beacons and public cards.</li>
 *   <li>{@link #syncWith}: handshake, HELLO both ways carrying log head and
 *       censor pin, then each side sends the log entries the other lacks, in
 *       frames that fit the transport. Entries are merged only if the pins
 *       match, and only through {@link HubLog#mergeEntries}, which checks every
 *       hash, link and signature.</li>
 *   <li>{@link #beacon}: a rolling, keyed beacon ({@link Beacon}), which only
 *       other replicas can recognise.</li>
 *   <li>{@link #verifyPresence}: whether a device has an authenticated
 *       session over the hub's Wi-Fi right now.</li>
 * </ul>
 *
 * <h2>Who it syncs with</h2>
 *
 * <p>Replicas of the same hub: hub instances holding the same issuer key, for
 * example an admin's desktop and phone. {@code authorise} decides which
 * session keys are let in, and the default admits only this service's own key.
 * Whether members' devices should also hold replicas of the hub log is a
 * policy question, not a transport one (README open question 24). The log
 * records who joined and who moderated, so every replica is one more device
 * that can be seized.
 */
public class SyncService implements Transport.FrameListener {

    /** Ordered by preference; the service picks the best one that can carry the job. */
    private List<Transport> transports;

    private String hubId;

    /** What a given sync job needs from a transport. */
    public enum Job {
        /** "I exist, here's my log head." Fits on LoRa. */
        HEARTBEAT(Beacon.SIZE, false, false, true),
        /** A single short meeting request. Fits on LoRa at SF7–8. */
        MEETING_REQUEST(200, false, false, false),
        /**
         * Public discovery cards. Small enough for Bluetooth mesh, and
         * deliberately gossiped rather than fetched: a card requested on demand
         * would tell its hub that someone nearby was looking for it.
         */
        CARD_GOSSIP(512, false, false, true),
        /** Recent log entries. Needs Bluetooth mesh or better. */
        LOG_DELTA(512, false, false, false),
        /**
         * Full skills layer and summaries. Needs Wi-Fi or cellular. Until
         * persistence exists (stage 3) this carries the log only, without
         * LOG_DELTA's frame limit.
         */
        FULL_SYNC(4096, true, false, false),
        /** Model artefact download. Wi-Fi only; hundreds of megabytes. Not yet implemented. */
        MODEL_FETCH(65536, true, true, false);

        private final int minBytes;
        private final boolean needsBulk;
        private final boolean wifiOnly;
        private final boolean broadcast;

        Job(int minBytes, boolean needsBulk, boolean wifiOnly, boolean broadcast) {
            this.minBytes = minBytes;
            this.needsBulk = needsBulk;
            this.wifiOnly = wifiOnly;
            this.broadcast = broadcast;
        }

        /** Whether this transport can carry this job at all. */
        public boolean fits(Transport t) {
            int capacity = broadcast ? t.maxBroadcastBytes() : t.maxPayloadBytes();
            return capacity >= minBytes && (!needsBulk || t.supportsBulkSync())
                    && (!wifiOnly || t.kind() == Transport.Kind.WIFI);
        }

        boolean carriesLog() {
            return this == LOG_DELTA || this == FULL_SYNC;
        }
    }

    /** Something delivered over a session: a meeting request, for now. */
    public record Delivery(Job job, byte[] payload) {
    }

    private final Signer channelKey;
    private final byte[] beaconKey;
    private final Clock clock;

    private volatile Hub servedHub;
    private volatile org.shalim.ml.ModelPin censorPin;
    private volatile Predicate<String> authorise;
    private volatile boolean allowObservable = true;
    private volatile Duration timeout = Duration.ofSeconds(10);
    private volatile Duration presenceWindow = Duration.ofMinutes(5);

    private volatile NetworkClaimService claimService;
    private volatile Signer claimKey;
    private volatile byte[] claimSalt;

    private volatile Consumer<byte[]> cardSink = c -> { };
    private volatile BiConsumer<PeerEndpoint, Delivery> deliverySink = (p, d) -> { };

    private final Map<String, Pending> pendingInitiators = new ConcurrentHashMap<>();
    private final Map<String, SecureChannel.Responder> pendingResponders = new ConcurrentHashMap<>();
    private final Map<String, Exchange> sessions = new ConcurrentHashMap<>();
    private final List<SyncOutcome> inboundOutcomes = new CopyOnWriteArrayList<>();

    /**
     * @param channelKey the key this device authenticates sessions with; for a
     *                   hub instance, the hub issuer key
     * @param beaconKey  shared by this hub's replicas ({@link Beacon#keyFrom}); null disables beacons
     */
    public SyncService(String hubId, List<Transport> transports, Signer channelKey, byte[] beaconKey, Clock clock) {
        this.hubId = hubId;
        this.transports = List.copyOf(transports);
        this.channelKey = channelKey;
        this.beaconKey = beaconKey == null ? null : beaconKey.clone();
        this.clock = clock;
        String own = channelKey.fingerprint();
        this.authorise = own::equals;
    }

    /** Sets this service as the listener on each transport. Use a {@link FrameRouter} to share one. */
    public SyncService attach() {
        for (Transport t : transports) {
            t.setListener(this);
        }
        return this;
    }

    // --- configuration ----------------------------------------------------

    /** The hub whose log this service serves to peers that sync with it. */
    public SyncService serve(Hub hub) {
        this.servedHub = hub;
        return this;
    }

    public SyncService withCensorPin(org.shalim.ml.ModelPin pin) {
        this.censorPin = pin;
        return this;
    }

    /** Which session keys may sync here. Defaults to this service's own key. */
    public SyncService authorising(Predicate<String> authorise) {
        this.authorise = authorise;
        return this;
    }

    /**
     * Whether observable transports (cellular, Bluetooth, LoRa, a café's
     * Wi-Fi) may be used at all. HIGH_RISK hubs turn this off.
     */
    public SyncService allowingObservable(boolean allow) {
        this.allowObservable = allow;
        return this;
    }

    public SyncService withTimeout(Duration timeout) {
        this.timeout = timeout;
        return this;
    }

    /** Makes this instance answer claim queries for its hub. */
    public SyncService answeringClaims(NetworkClaimService service, Signer hubKey, byte[] hubSalt) {
        this.claimService = service;
        this.claimKey = hubKey;
        this.claimSalt = hubSalt.clone();
        return this;
    }

    public SyncService onCard(Consumer<byte[]> sink) {
        this.cardSink = sink;
        return this;
    }

    public SyncService onDelivery(BiConsumer<PeerEndpoint, Delivery> sink) {
        this.deliverySink = sink;
        return this;
    }

    // --- transport selection ----------------------------------------------

    /** Best available transport that can actually carry the job, if any. */
    public Transport selectTransport(Job job) {
        for (Transport t : transports) {
            if (usable(t) && job.fits(t)) {
                return t;
            }
        }
        return null;
    }

    public boolean canPerform(Job job) {
        return selectTransport(job) != null;
    }

    private boolean usable(Transport t) {
        return t.isAvailable() && (allowObservable || !t.isObservable());
    }

    private Transport transportFor(PeerEndpoint peer) {
        for (Transport t : transports) {
            if (t.kind() == peer.getVia() && usable(t)) {
                return t;
            }
        }
        return null;
    }

    // --- syncing ----------------------------------------------------------

    /** Exchanges log entries with one peer and merges what comes back. */
    public SyncOutcome syncWith(PeerEndpoint peer, Hub localHub, Job job) {
        SyncOutcome outcome = new SyncOutcome(peer.getEndpointId(), job);
        Transport t = transportFor(peer);
        if (t == null || !job.fits(t)) {
            return outcome.fail("no usable transport can carry " + job + " to this peer");
        }
        if (job == Job.HEARTBEAT) {
            // Spend no airtime on a handshake: the beacon already told us.
            String ours = localHub.getLog().getHeadHash();
            String theirs = peer.getAdvertisedLogHead();
            return java.util.Objects.equals(ours, theirs) ? outcome.succeed()
                    : outcome.fail("heads differ; needs LOG_DELTA or better");
        }
        if (!job.carriesLog()) {
            return outcome.fail(job + " is not a sync job; use deliver()");
        }
        Exchange ex;
        try {
            ex = ensureSession(peer, t);
        } catch (SecureChannel.ChannelException | TimeoutException e) {
            return outcome.fail("session: " + e.getMessage());
        }
        ex.begin(localHub, job, outcome);
        ex.sendHello();
        try {
            ex.finished.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            return outcome.fail("peer did not finish in time");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return outcome.fail("interrupted");
        } catch (ExecutionException e) {
            return outcome.fail(String.valueOf(e.getCause().getMessage()));
        }
        return outcome;
    }

    /** Opportunistic sync with every reachable replica that is behind or ahead. */
    public List<SyncOutcome> syncAll(Hub localHub) {
        List<SyncOutcome> out = new ArrayList<>();
        String ours = localHub.getLog().getHeadHash();
        for (Transport t : transports) {
            if (!usable(t)) {
                continue;
            }
            for (PeerEndpoint peer : t.discoverPeers()) {
                if (hubId == null || !hubId.equals(peer.getHubId())) {
                    continue; // only replicas we have recognised by beacon
                }
                if (java.util.Objects.equals(ours, peer.getAdvertisedLogHead())) {
                    continue; // nothing to do, and no airtime spent finding that out
                }
                Job job = Job.FULL_SYNC.fits(t) ? Job.FULL_SYNC
                        : Job.LOG_DELTA.fits(t) ? Job.LOG_DELTA : Job.HEARTBEAT;
                out.add(syncWith(peer, localHub, job));
            }
        }
        return out;
    }

    /** Periodic presence beacon; the only thing worth spending LoRa airtime on. */
    public boolean beacon(Hub localHub) {
        if (beaconKey == null) {
            return false;
        }
        Transport t = selectTransport(Job.HEARTBEAT);
        if (t == null) {
            return false;
        }
        return t.broadcast(Beacon.create(beaconKey, localHub.getLog().getHeadHash(), clock.instant()));
    }

    /** Beacons on every usable transport that can carry one, not only the best. */
    public int beaconEverywhere(Hub localHub) {
        if (beaconKey == null) {
            return 0;
        }
        byte[] frame = Beacon.create(beaconKey, localHub.getLog().getHeadHash(), clock.instant());
        int sent = 0;
        for (Transport t : transports) {
            if (usable(t) && Job.HEARTBEAT.fits(t) && t.broadcast(frame)) {
                sent++;
            }
        }
        return sent;
    }

    /** Sends one small payload (a meeting request) over an authenticated session. */
    public boolean deliver(PeerEndpoint peer, Job job, byte[] payload) {
        if (job != Job.MEETING_REQUEST) {
            throw new IllegalArgumentException("deliver() carries meeting requests; cards go through gossip()");
        }
        Transport t = transportFor(peer);
        if (t == null || !job.fits(t)) {
            return false;
        }
        byte[] inner = Wire.writer().u8(MessageType.DELIVERY).u8(Wire.ordinal(job)).bytes(payload).done();
        if (inner.length + SecureChannel.Session.overhead() > t.maxPayloadBytes()) {
            return false;
        }
        try {
            Exchange ex = ensureSession(peer, t);
            return t.send(peer, ex.session.seal(inner));
        } catch (SecureChannel.ChannelException | TimeoutException e) {
            return false;
        }
    }

    /** Gossips a public card to whoever is in range. */
    public boolean gossip(byte[] card) {
        Transport t = selectTransport(Job.CARD_GOSSIP);
        byte[] frame = Bytes.concat(new byte[] {(byte) MessageType.CARD}, card);
        return t != null && frame.length <= t.maxBroadcastBytes() && t.broadcast(frame);
    }

    // --- guest presence ---------------------------------------------------

    /**
     * Confirms a guest is on the hub's verified network. Guest access is scoped
     * to physical presence, so this must be re-checked, not cached indefinitely.
     * True only if the device holds an authenticated session with this hub
     * instance over this Wi-Fi transport, and has been heard from within the
     * presence window.
     */
    public boolean verifyPresence(String userId, Transport transport) {
        if (userId == null || transport == null || transport.kind() != Transport.Kind.WIFI
                || !transport.isAvailable() || !transports.contains(transport)) {
            return false;
        }
        Instant cutoff = clock.instant().minus(presenceWindow);
        for (Exchange ex : sessions.values()) {
            PeerEndpoint p = ex.peer;
            if (ex.transport == transport && p.isAuthenticated() && userId.equals(p.getPeerUserId())
                    && p.getLastContactAt() != null && p.getLastContactAt().isAfter(cutoff)) {
                return true;
            }
        }
        return false;
    }

    /** Outcomes of syncs that peers started with this service. */
    public List<SyncOutcome> getInboundOutcomes() {
        return List.copyOf(inboundOutcomes);
    }

    // --- sessions ---------------------------------------------------------

    private Exchange ensureSession(PeerEndpoint peer, Transport t)
            throws SecureChannel.ChannelException, TimeoutException {
        for (Exchange ex : sessions.values()) {
            if (ex.peer.equals(peer) && ex.transport == t && ex.session.isInitiator()) {
                return ex;
            }
        }
        SecureChannel.Initiator init = SecureChannel.initiate(channelKey, null);
        Pending pending = new Pending(init, peer, t);
        String sid = Bytes.hex(init.sessionId());
        pendingInitiators.put(sid, pending);
        try {
            if (!t.send(peer, init.firstMessage())) {
                throw new SecureChannel.ChannelException("could not send handshake");
            }
            return pending.done.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new SecureChannel.ChannelException("interrupted");
        } catch (ExecutionException e) {
            throw new SecureChannel.ChannelException(String.valueOf(e.getCause().getMessage()));
        } finally {
            pendingInitiators.remove(sid);
        }
    }

    private static String sessionKey(PeerEndpoint peer, byte[] sid) {
        return peer.getEndpointId() + "|" + Bytes.hex(sid);
    }

    // --- incoming ---------------------------------------------------------

    @Override
    public void onFrame(PeerEndpoint from, byte[] frame) {
        if (frame == null || frame.length == 0) {
            return;
        }
        Transport via = transportFor(from);
        if (via == null) {
            return;
        }
        try {
            switch (frame[0] & 0xff) {
                case MessageType.HANDSHAKE_1 -> onHandshake1(from, via, frame);
                case MessageType.HANDSHAKE_2 -> onHandshake2(frame);
                case MessageType.HANDSHAKE_3 -> onHandshake3(from, via, frame);
                case MessageType.SEALED -> onSealed(from, frame);
                case MessageType.CLAIM_QUERY -> onClaimQuery(from, via, frame);
                case MessageType.BEACON -> onBeacon(from, frame);
                case MessageType.CARD -> cardSink.accept(java.util.Arrays.copyOfRange(frame, 1, frame.length));
                default -> {
                    // CLAIM_ANSWER is for ClaimQueryClient; anything else is unknown. Dropped.
                }
            }
        } catch (Wire.WireException | SecureChannel.ChannelException e) {
            // A malformed or unauthenticated frame is dropped, never answered.
        }
    }

    private void onHandshake1(PeerEndpoint from, Transport via, byte[] frame) throws SecureChannel.ChannelException {
        if (pendingResponders.size() > 256) {
            return; // handshake flood; refuse new ones until old ones finish or expire
        }
        SecureChannel.Responder r = SecureChannel.Responder.accept(frame, channelKey);
        pendingResponders.put(sessionKey(from, r.sessionId()), r);
        via.send(from, r.response());
    }

    private void onHandshake2(byte[] frame) throws SecureChannel.ChannelException {
        byte[] sid = SecureChannel.sessionIdOf(frame);
        Pending p = sid == null ? null : pendingInitiators.get(Bytes.hex(sid));
        if (p == null) {
            return;
        }
        try {
            SecureChannel.Session s = p.initiator.onResponse(frame);
            Predicate<String> auth = authorise;
            if (auth != null && !auth.test(s.remoteFingerprint())) {
                throw new SecureChannel.ChannelException("responder not authorised");
            }
            if (!p.transport.send(p.peer, p.initiator.finalMessage())) {
                throw new SecureChannel.ChannelException("could not send handshake");
            }
            p.peer.authenticated(s, clock.instant());
            Exchange ex = new Exchange(s, p.peer, p.transport);
            sessions.put(sessionKey(p.peer, s.sessionId()), ex);
            p.done.complete(ex);
        } catch (SecureChannel.ChannelException e) {
            p.done.completeExceptionally(e);
        }
    }

    private void onHandshake3(PeerEndpoint from, Transport via, byte[] frame) throws SecureChannel.ChannelException {
        byte[] sid = SecureChannel.sessionIdOf(frame);
        if (sid == null) {
            return;
        }
        SecureChannel.Responder r = pendingResponders.remove(sessionKey(from, sid));
        if (r == null) {
            return;
        }
        SecureChannel.Session s = r.onFinish(frame, authorise);
        from.authenticated(s, clock.instant());
        sessions.put(sessionKey(from, sid), new Exchange(s, from, via));
    }

    private void onSealed(PeerEndpoint from, byte[] frame) throws SecureChannel.ChannelException {
        byte[] sid = SecureChannel.sessionIdOf(frame);
        Exchange ex = sid == null ? null : sessions.get(sessionKey(from, sid));
        if (ex == null) {
            return;
        }
        byte[] inner = ex.session.open(frame);
        from.contact(clock.instant());
        try {
            ex.onInner(inner);
        } catch (RuntimeException e) {
            // A frame that authenticated but does not make sense ends this exchange.
            ex.abort(e);
        }
    }

    private void onClaimQuery(PeerEndpoint from, Transport via, byte[] frame) {
        NetworkClaimService service = claimService;
        if (service == null) {
            return;
        }
        ClaimFrames.Query q = ClaimFrames.readQuery(frame);
        ClaimAnswer answer = service.answer(q.nonce(), q.bssid(), claimKey, claimSalt);
        if (answer != null) {
            via.send(from, ClaimFrames.answer(q.nonce(), answer));
        }
    }

    private void onBeacon(PeerEndpoint from, byte[] frame) {
        if (beaconKey == null) {
            return;
        }
        Beacon.Sighting s = Beacon.recognise(frame, beaconKey, clock.instant());
        if (s != null) {
            from.recognisedAs(hubId);
            from.advertised(s.logHead(), null);
        }
    }

    // --- one session's sync state ------------------------------------------

    private static final class Pending {
        final SecureChannel.Initiator initiator;
        final PeerEndpoint peer;
        final Transport transport;
        final CompletableFuture<Exchange> done = new CompletableFuture<>();

        Pending(SecureChannel.Initiator initiator, PeerEndpoint peer, Transport transport) {
            this.initiator = initiator;
            this.peer = peer;
            this.transport = transport;
        }
    }

    /**
     * The sync conversation on one session. Symmetric: whichever side receives
     * a HELLO answers with its own (if it has not sent one), then sends the
     * entries the other lacks, then DONE. Each side merges on the other's DONE.
     */
    private final class Exchange {
        final SecureChannel.Session session;
        final PeerEndpoint peer;
        final Transport transport;
        volatile CompletableFuture<Void> finished = new CompletableFuture<>();

        private Hub hub;
        private Job job;
        private SyncOutcome outcome;
        private boolean helloSent;
        private boolean deltaSent;
        private boolean pinsMatch;
        private final List<HubLog.Entry> received = new ArrayList<>();
        private boolean peerDone;

        Exchange(SecureChannel.Session session, PeerEndpoint peer, Transport transport) {
            this.session = session;
            this.peer = peer;
            this.transport = transport;
        }

        synchronized void begin(Hub localHub, Job job, SyncOutcome outcome) {
            this.hub = localHub;
            this.job = job;
            this.outcome = outcome;
            this.helloSent = false;
            this.deltaSent = false;
            this.peerDone = false;
            this.received.clear();
            this.finished = new CompletableFuture<>();
        }

        synchronized void sendHello() {
            String pin = censorPin == null ? null : censorPin.getArtefactHash();
            byte[] hello = Wire.writer().u8(MessageType.HELLO).u8(Wire.ordinal(job))
                    .hex(hub.getLog().getHeadHash()).hex(pin).done();
            helloSent = true;
            send(hello);
        }

        synchronized void onInner(byte[] inner) {
            Wire.Reader r = Wire.reader(inner);
            switch (r.u8()) {
                case MessageType.HELLO -> onHello(r);
                case MessageType.LOG_ENTRIES -> onEntries(r);
                case MessageType.DONE -> onDone(r);
                case MessageType.DELIVERY -> onDelivery(r);
                default -> throw new Wire.WireException("unknown inner message");
            }
        }

        private void onHello(Wire.Reader r) {
            Job peerJob = r.enumValue(Job.class);
            String peerHead = r.hex();
            String peerPin = r.hex();
            r.end();
            if (peerJob == null || !peerJob.carriesLog()) {
                throw new Wire.WireException("bad job");
            }
            peer.advertised(peerHead, peerPin);
            if (hub == null) {
                // We are the responder: a peer started this exchange.
                Hub served = servedHub;
                if (served == null) {
                    return;
                }
                begin(served, peerJob, new SyncOutcome(peer.getEndpointId(), peerJob));
            }
            String ours = censorPin == null ? null : censorPin.getArtefactHash();
            pinsMatch = ours != null && peerPin != null && Bytes.equalHex(ours, peerPin);
            outcome.censorMismatch = !pinsMatch;
            if (!helloSent) {
                sendHello();
            }
            if (!deltaSent) {
                sendDelta(peerHead);
            }
            maybeFinish();
        }

        private void sendDelta(String peerHead) {
            deltaSent = true;
            int sent = 0;
            if (pinsMatch) {
                List<HubLog.Entry> missing = hub.getLog().entriesMissingFrom(peerHead);
                int limit = transport.maxPayloadBytes() - SecureChannel.Session.overhead();
                if (job == Job.LOG_DELTA) {
                    limit = Math.min(limit, TransportProfile.BLUETOOTH_MAX_FRAME - SecureChannel.Session.overhead());
                }
                List<byte[]> batch = new ArrayList<>();
                int batchBytes = 3;
                for (HubLog.Entry e : missing) {
                    Wire.Writer one = Wire.writer();
                    LogEntryCodec.write(one, e);
                    byte[] encoded = one.done();
                    if (3 + encoded.length > limit) {
                        break; // cannot fit even alone on this transport; stop, rather than skip and break the chain
                    }
                    if (batchBytes + encoded.length > limit || batch.size() == 0xffff) {
                        sendEntries(batch);
                        batch.clear();
                        batchBytes = 3;
                    }
                    batch.add(encoded);
                    batchBytes += encoded.length;
                    sent++;
                }
                if (!batch.isEmpty()) {
                    sendEntries(batch);
                }
            }
            outcome.entriesSent = sent;
            send(Wire.writer().u8(MessageType.DONE).u32(sent).done());
        }

        private void sendEntries(List<byte[]> batch) {
            Wire.Writer w = Wire.writer().u8(MessageType.LOG_ENTRIES).u8(batch.size() >>> 8).u8(batch.size());
            byte[] head = w.done();
            byte[][] parts = new byte[batch.size() + 1][];
            parts[0] = head;
            for (int i = 0; i < batch.size(); i++) {
                parts[i + 1] = batch.get(i);
            }
            send(Bytes.concat(parts));
        }

        private void onEntries(Wire.Reader r) {
            if (hub == null || !pinsMatch) {
                return;
            }
            int n = (r.u8() << 8) | r.u8();
            for (int i = 0; i < n; i++) {
                received.add(LogEntryCodec.read(r));
            }
            r.end();
            if (received.size() > 100_000) {
                throw new Wire.WireException("too many entries");
            }
        }

        private void onDone(Wire.Reader r) {
            long announced = r.u32();
            r.end();
            if (hub == null) {
                return;
            }
            peerDone = true;
            if (pinsMatch) {
                if (announced != received.size()) {
                    outcome.failureReason = "peer announced " + announced + " entries, sent " + received.size();
                }
                // Replicas usually share one key, so this map often has one entry.
                Map<String, byte[]> keys = new java.util.HashMap<>();
                keys.put(channelKey.fingerprint(), channelKey.publicKey());
                keys.put(session.remoteFingerprint(), session.remotePublicKey());
                Function<String, byte[]> lookup = keys::get;
                outcome.entriesReceived = hub.getLog().mergeEntries(new ArrayList<>(received), lookup);
            }
            maybeFinish();
        }

        private void onDelivery(Wire.Reader r) {
            Job j = r.enumValue(Job.class);
            byte[] payload = r.bytes(TransportProfile.WIFI_MAX_FRAME);
            r.end();
            if (j == Job.MEETING_REQUEST && payload != null) {
                deliverySink.accept(peer, new Delivery(j, payload));
            }
        }

        private void maybeFinish() {
            if (helloSent && deltaSent && peerDone && !finished.isDone()) {
                outcome.succeeded = outcome.failureReason == null && pinsMatch;
                if (!pinsMatch && outcome.failureReason == null) {
                    outcome.failureReason = "censor pins differ; nothing merged";
                }
                if (!session.isInitiator()) {
                    inboundOutcomes.add(outcome);
                }
                hub = session.isInitiator() ? hub : null; // a responder is ready for the next exchange
                finished.complete(null);
            }
        }

        private void send(byte[] inner) {
            transport.send(peer, session.seal(inner));
        }

        synchronized void abort(RuntimeException cause) {
            if (outcome != null && outcome.failureReason == null) {
                outcome.failureReason = "exchange aborted: " + cause.getMessage();
            }
            if (!session.isInitiator()) {
                hub = null;
            }
            finished.completeExceptionally(cause);
        }
    }

    /** Result of one peer exchange. */
    public static class SyncOutcome {
        private final String peerEndpointId;
        private final Job job;
        private boolean succeeded;
        private int entriesReceived;
        private int entriesSent;

        /** Set when the peer's censor pin did not match ours. */
        private boolean censorMismatch;

        private String failureReason;

        SyncOutcome(String peerEndpointId, Job job) {
            this.peerEndpointId = peerEndpointId;
            this.job = job;
        }

        SyncOutcome fail(String reason) {
            this.succeeded = false;
            this.failureReason = reason;
            return this;
        }

        SyncOutcome succeed() {
            this.succeeded = true;
            return this;
        }

        public boolean isSucceeded() {
            return succeeded;
        }

        public boolean hasCensorMismatch() {
            return censorMismatch;
        }

        public int getEntriesReceived() {
            return entriesReceived;
        }

        public int getEntriesSent() {
            return entriesSent;
        }

        public String getFailureReason() {
            return failureReason;
        }

        public String getPeerEndpointId() {
            return peerEndpointId;
        }

        public Job getJob() {
            return job;
        }
    }
}
