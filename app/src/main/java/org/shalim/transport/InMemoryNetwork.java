package org.shalim.transport;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A simulated medium that devices join, with the capacity limits of a real
 * one. It is used by the tests and by a desktop harness to run several hubs
 * and devices in one process. Frames are delivered asynchronously, one thread
 * per device, as on a real network. Each kind of transport is its own medium:
 * a Wi-Fi frame never reaches a LoRa device.
 *
 * <p>{@link #observed()} records every frame on an observable medium, so tests
 * can check what an eavesdropper would see.
 */
public final class InMemoryNetwork {

    private final Clock clock;
    private final Map<String, InMemoryTransport> members = new ConcurrentHashMap<>();
    private final List<byte[]> observed = new CopyOnWriteArrayList<>();
    private final AtomicInteger delivered = new AtomicInteger();

    public InMemoryNetwork(Clock clock) {
        this.clock = clock;
    }

    public InMemoryNetwork() {
        this(Clock.systemUTC());
    }

    /** Joins a device at {@code address}. LoRa profiles get airtime accounting at {@code spreadingFactor}. */
    public InMemoryTransport join(String address, TransportProfile profile) {
        return join(address, profile, 7);
    }

    public InMemoryTransport join(String address, TransportProfile profile, int spreadingFactor) {
        InMemoryTransport t = new InMemoryTransport(address, profile, spreadingFactor);
        if (members.putIfAbsent(key(profile.kind(), address), t) != null) {
            throw new IllegalArgumentException("address taken: " + address);
        }
        return t;
    }

    /** Frames seen on observable media, as an eavesdropper would see them. */
    public List<byte[]> observed() {
        return new ArrayList<>(observed);
    }

    public int deliveredCount() {
        return delivered.get();
    }

    private static String key(Transport.Kind kind, String address) {
        return kind + "|" + address;
    }

    /** One device's attachment to the medium. */
    public final class InMemoryTransport implements Transport {
        private final String address;
        private final TransportProfile profile;
        private final int spreadingFactor;
        private final AirtimeBudget budget;
        private final ExecutorService inbox;
        private final Map<String, PeerEndpoint> endpoints = new ConcurrentHashMap<>();
        private volatile FrameListener listener;
        private volatile boolean available = true;

        private InMemoryTransport(String address, TransportProfile profile, int spreadingFactor) {
            this.address = address;
            this.profile = profile;
            this.spreadingFactor = spreadingFactor;
            this.budget = profile.dutyCycle() < 1.0 ? AirtimeBudget.hourly(profile.dutyCycle()) : null;
            this.inbox = Executors.newSingleThreadExecutor(r -> {
                Thread th = new Thread(r, "inmem-" + address);
                th.setDaemon(true);
                return th;
            });
        }

        @Override
        public Kind kind() {
            return profile.kind();
        }

        @Override
        public boolean isAvailable() {
            return available;
        }

        /** Simulates the radio going down or the device leaving the network. */
        public void setAvailable(boolean available) {
            this.available = available;
        }

        @Override
        public int maxPayloadBytes() {
            return profile.maxPayloadBytes();
        }

        @Override
        public int maxBroadcastBytes() {
            return profile.maxBroadcastBytes();
        }

        @Override
        public double dutyCycle() {
            return profile.dutyCycle();
        }

        @Override
        public boolean supportsBulkSync() {
            return profile.supportsBulkSync();
        }

        @Override
        public boolean isObservable() {
            return profile.observable();
        }

        public String address() {
            return address;
        }

        /** Seconds of airtime left this hour; infinite for media without a duty cycle. */
        public double airtimeRemaining() {
            return budget == null ? Double.POSITIVE_INFINITY : budget.remaining(clock.instant());
        }

        @Override
        public List<PeerEndpoint> discoverPeers() {
            List<PeerEndpoint> out = new ArrayList<>();
            for (InMemoryTransport t : members.values()) {
                if (t != this && t.profile.kind() == profile.kind() && t.available) {
                    out.add(endpointFor(t.address));
                }
            }
            return out;
        }

        @Override
        public boolean send(PeerEndpoint peer, byte[] payload) {
            if (peer == null || payload.length > profile.maxPayloadBytes()) {
                return false;
            }
            InMemoryTransport target = members.get(key(profile.kind(), peer.getAddress()));
            if (target == null || !transmit(payload)) {
                return false;
            }
            return target.deliver(address, payload);
        }

        @Override
        public boolean broadcast(byte[] payload) {
            if (payload.length > profile.maxBroadcastBytes() || !transmit(payload)) {
                return false;
            }
            for (InMemoryTransport t : members.values()) {
                if (t != this && t.profile.kind() == profile.kind()) {
                    t.deliver(address, payload);
                }
            }
            return true;
        }

        /** Checks availability and airtime, and records what an eavesdropper sees. */
        private boolean transmit(byte[] payload) {
            if (!available) {
                return false;
            }
            if (budget != null) {
                double seconds = LoRaAirtime.seconds(payload.length, spreadingFactor);
                if (!budget.trySpend(seconds, clock.instant())) {
                    return false;
                }
            }
            if (profile.observable()) {
                observed.add(payload.clone());
            }
            return true;
        }

        private boolean deliver(String fromAddress, byte[] payload) {
            if (!available || inbox.isShutdown()) {
                return false;
            }
            byte[] copy = payload.clone();
            inbox.execute(() -> {
                FrameListener l = listener;
                if (l != null) {
                    PeerEndpoint from = endpointFor(fromAddress);
                    from.contact(Instant.now(clock));
                    delivered.incrementAndGet();
                    try {
                        l.onFrame(from, copy);
                    } catch (RuntimeException e) {
                        // A listener bug must not kill the device's inbox.
                    }
                }
            });
            return true;
        }

        private PeerEndpoint endpointFor(String peerAddress) {
            return endpoints.computeIfAbsent(peerAddress, a -> new PeerEndpoint(profile.kind(), a));
        }

        @Override
        public void setListener(FrameListener listener) {
            this.listener = listener;
        }

        @Override
        public void close() {
            available = false;
            members.remove(key(profile.kind(), address), this);
            inbox.shutdown();
            try {
                inbox.awaitTermination(1, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }
}
