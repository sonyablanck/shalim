package org.shalim.transport;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import org.shalim.crypto.Bytes;
import org.shalim.crypto.Hashing;
import org.shalim.crypto.SoftwareSigner;
import org.shalim.hub.Hub;
import org.shalim.hub.HubLog;
import org.shalim.ml.ModelPin;
import org.shalim.testing.Check;

/** Replica sync over the in-memory medium. */
public final class SyncServiceTest {

    private static final Instant T0 = Instant.parse("2026-10-29T09:00:00Z");
    private static final ModelPin PIN = new ModelPin(ModelPin.Purpose.CENSOR, "TinyCensor", "1",
            Hashing.sha256Hex("weights"), "cpu-ref", "int8");

    private SyncServiceTest() {
    }

    /** Two replicas of one hub, sharing its key and beacon key. */
    private static final class Pair {
        final SoftwareSigner hubKey = SoftwareSigner.generate();
        final byte[] beaconKey = Beacon.keyFrom(Bytes.random(32));
        final InMemoryNetwork net = new InMemoryNetwork(Clock.systemUTC());
        final Hub hubA = new Hub("hub-1", "Library", null, null, null, null);
        final Hub hubB = new Hub("hub-1", "Library", null, null, null, null);
        final InMemoryNetwork.InMemoryTransport ta;
        final InMemoryNetwork.InMemoryTransport tb;
        final SyncService a;
        final SyncService b;

        Pair(TransportProfile profile) {
            ta = net.join("A", profile);
            tb = net.join("B", profile);
            a = new SyncService("hub-1", List.of(ta), hubKey, beaconKey, Clock.systemUTC())
                    .withCensorPin(PIN).serve(hubA).withTimeout(Duration.ofSeconds(5)).attach();
            b = new SyncService("hub-1", List.of(tb), hubKey, beaconKey, Clock.systemUTC())
                    .withCensorPin(PIN).serve(hubB).withTimeout(Duration.ofSeconds(5)).attach();
        }

        void append(Hub hub, int n, String detail) {
            for (int i = 0; i < n; i++) {
                hub.getLog().append(HubLog.EventType.SYNC_COMPLETED, "admin", null, detail + i, hubKey,
                        T0.plusSeconds(i));
            }
        }

        PeerEndpoint peerOf(InMemoryNetwork.InMemoryTransport from) {
            return from.discoverPeers().get(0);
        }

        void close() {
            ta.close();
            tb.close();
        }
    }

    public static void testReplicaCatchesUpOverWifi() {
        Pair p = new Pair(TransportProfile.wifi(false));
        try {
            p.append(p.hubA, 5, "a");
            SyncService.SyncOutcome out = p.b.syncWith(p.peerOf(p.tb), p.hubB, SyncService.Job.FULL_SYNC);
            Check.isTrue(out.isSucceeded(), "succeeded: " + out.getFailureReason());
            Check.equal(5, out.getEntriesReceived(), "five entries arrived");
            Check.equal(p.hubA.getLog().getHeadHash(), p.hubB.getLog().getHeadHash(), "heads converge");
            Check.isTrue(p.hubB.getLog().verifyChain(fp -> p.hubKey.publicKey()), "replica chain verifies");
            Check.equal(1, p.a.getInboundOutcomes().size(), "responder recorded the exchange");
        } finally {
            p.close();
        }
    }

    public static void testSyncRunsBothWaysAndRepeats() {
        Pair p = new Pair(TransportProfile.wifi(false));
        try {
            p.append(p.hubB, 3, "b");
            PeerEndpoint aToB = p.peerOf(p.ta);
            SyncService.SyncOutcome first = p.a.syncWith(aToB, p.hubA, SyncService.Job.FULL_SYNC);
            Check.equal(3, first.getEntriesReceived(), "initiator pulls");
            p.append(p.hubA, 2, "a2-");
            SyncService.SyncOutcome second = p.a.syncWith(aToB, p.hubA, SyncService.Job.FULL_SYNC);
            Check.isTrue(second.isSucceeded(), "second exchange on the same session");
            Check.equal(2, second.getEntriesSent(), "initiator pushes");
            waitFor(() -> p.hubB.getLog().getHeadHash().equals(p.hubA.getLog().getHeadHash()));
            Check.equal(p.hubA.getLog().getHeadHash(), p.hubB.getLog().getHeadHash(), "converged both ways");
        } finally {
            p.close();
        }
    }

    public static void testCensorMismatchMergesNothing() {
        Pair p = new Pair(TransportProfile.wifi(false));
        try {
            p.b.withCensorPin(new ModelPin(ModelPin.Purpose.CENSOR, "TinyCensor", "1",
                    Hashing.sha256Hex("retuned"), "cpu-ref", "int8"));
            p.append(p.hubA, 4, "a");
            SyncService.SyncOutcome out = p.b.syncWith(p.peerOf(p.tb), p.hubB, SyncService.Job.FULL_SYNC);
            Check.isTrue(out.hasCensorMismatch(), "mismatch flagged");
            Check.isFalse(out.isSucceeded(), "not a success");
            Check.equal(0, p.hubB.getLog().getEntries().size(), "nothing merged");
        } finally {
            p.close();
        }
    }

    public static void testUnauthorisedKeyGetsNoSession() {
        Pair p = new Pair(TransportProfile.wifi(false));
        try {
            p.append(p.hubA, 2, "a");
            InMemoryNetwork.InMemoryTransport tc = p.net.join("C", TransportProfile.wifi(false));
            Hub stranger = new Hub("hub-1", "Library", null, null, null, null);
            SyncService c = new SyncService("hub-1", List.of(tc), SoftwareSigner.generate(), null,
                    Clock.systemUTC()).withCensorPin(PIN).serve(stranger).withTimeout(Duration.ofSeconds(2))
                    .authorising(fp -> true).attach();
            PeerEndpoint toA = tc.discoverPeers().stream().filter(e -> e.getAddress().equals("A")).findFirst().get();
            SyncService.SyncOutcome out = c.syncWith(toA, stranger, SyncService.Job.FULL_SYNC);
            Check.isFalse(out.isSucceeded(), "refused");
            Check.equal(0, stranger.getLog().getEntries().size(), "learnt nothing");
            tc.close();
        } finally {
            p.close();
        }
    }

    public static void testBluetoothDeltaFitsFramesAndLoRaCarriesBeaconsOnly() {
        Pair bt = new Pair(TransportProfile.bluetoothMesh());
        try {
            bt.append(bt.hubA, 12, "entry-");
            Check.isFalse(SyncService.Job.FULL_SYNC.fits(bt.tb), "no bulk sync over Bluetooth");
            SyncService.SyncOutcome out = bt.b.syncWith(bt.peerOf(bt.tb), bt.hubB, SyncService.Job.LOG_DELTA);
            Check.isTrue(out.isSucceeded(), "delta over Bluetooth: " + out.getFailureReason());
            Check.equal(12, out.getEntriesReceived(), "in frames of at most 512 bytes");
        } finally {
            bt.close();
        }
        Pair lora = new Pair(TransportProfile.lora(9));
        try {
            Check.isFalse(lora.b.canPerform(SyncService.Job.LOG_DELTA), "no log over LoRa");
            Check.isTrue(lora.b.canPerform(SyncService.Job.HEARTBEAT), "beacons fit");
            lora.append(lora.hubA, 1, "a");
            Check.isTrue(lora.a.beacon(lora.hubA), "beacon sent");
            PeerEndpoint aSeenFromB = lora.peerOf(lora.tb);
            waitFor(() -> lora.hubA.getLog().getHeadHash().equals(aSeenFromB.getAdvertisedLogHead()));
            Check.equal("hub-1", aSeenFromB.getHubId(), "replica recognised from its beacon");
            SyncService.SyncOutcome hb = lora.b.syncWith(aSeenFromB, lora.hubB, SyncService.Job.HEARTBEAT);
            Check.isFalse(hb.isSucceeded(), "heartbeat reports the gap without a handshake");
            Check.isTrue(Math.abs(lora.tb.airtimeRemaining() - 36.0) < 1e-9, "B spent no airtime finding out");
        } finally {
            lora.close();
        }
    }

    public static void testSyncAllUsesBeaconsToFindReplicas() {
        Pair p = new Pair(TransportProfile.wifi(false));
        try {
            p.append(p.hubA, 3, "a");
            Check.equal(0, p.b.syncAll(p.hubB).size(), "nobody recognised yet");
            p.a.beacon(p.hubA);
            waitFor(() -> "hub-1".equals(p.peerOf(p.tb).getHubId()));
            List<SyncService.SyncOutcome> outs = p.b.syncAll(p.hubB);
            Check.equal(1, outs.size(), "one replica synced");
            Check.equal(3, outs.get(0).getEntriesReceived(), "caught up");
            p.a.beacon(p.hubA);
            waitFor(() -> p.hubA.getLog().getHeadHash().equals(p.peerOf(p.tb).getAdvertisedLogHead()));
            Check.equal(0, p.b.syncAll(p.hubB).size(), "in sync, so nothing to do");
        } finally {
            p.close();
        }
    }

    public static void testEavesdropperSeesNoLogContent() {
        Pair p = new Pair(TransportProfile.wifi(true));
        try {
            p.append(p.hubA, 3, "secret-detail-");
            p.b.syncWith(p.peerOf(p.tb), p.hubB, SyncService.Job.FULL_SYNC);
            Check.isTrue(p.net.observed().size() > 3, "frames were observed");
            byte[] needle = "secret-detail-".getBytes(StandardCharsets.UTF_8);
            byte[] keyNeedle = p.hubKey.publicKey();
            for (byte[] frame : p.net.observed()) {
                Check.isFalse(contains(frame, needle), "no plaintext detail on the wire");
                Check.isFalse(contains(frame, keyNeedle), "no hub key on the wire");
            }
        } finally {
            p.close();
        }
    }

    public static void testPresenceAndDelivery() {
        Pair p = new Pair(TransportProfile.wifi(false));
        try {
            CompletableFuture<String> got = new CompletableFuture<>();
            p.a.onDelivery((peer, d) -> got.complete(new String(d.payload(), StandardCharsets.UTF_8)));
            PeerEndpoint toA = p.peerOf(p.tb);
            Check.isTrue(p.b.deliver(toA, SyncService.Job.MEETING_REQUEST,
                    "Grafting help, Thursday?".getBytes(StandardCharsets.UTF_8)), "sent");
            Check.equal("Grafting help, Thursday?", got.get(5, TimeUnit.SECONDS), "delivered over the session");
            Check.isTrue(p.a.verifyPresence(p.hubKey.fingerprint(), p.ta), "authenticated and recent over Wi-Fi");
            Check.isFalse(p.a.verifyPresence(SoftwareSigner.generate().fingerprint(), p.ta), "unknown key");
        } catch (Exception e) {
            throw new AssertionError(e);
        } finally {
            p.close();
        }
    }

    public static void testObservableTransportsCanBeRefused() {
        Pair p = new Pair(TransportProfile.cellular());
        try {
            Check.isTrue(p.a.canPerform(SyncService.Job.FULL_SYNC), "allowed by default");
            p.a.allowingObservable(false);
            Check.isFalse(p.a.canPerform(SyncService.Job.FULL_SYNC), "HIGH_RISK posture refuses cellular");
        } finally {
            p.close();
        }
    }

    static boolean contains(byte[] hay, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= hay.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (hay[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }

    static void waitFor(java.util.function.BooleanSupplier condition) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError("timed out waiting");
            }
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }
}
