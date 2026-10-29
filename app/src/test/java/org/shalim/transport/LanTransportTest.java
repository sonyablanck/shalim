package org.shalim.transport;

import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.shalim.crypto.Bytes;
import org.shalim.crypto.Hashing;
import org.shalim.crypto.SoftwareSigner;
import org.shalim.hub.Hub;
import org.shalim.hub.HubLog;
import org.shalim.hub.HubNetwork;
import org.shalim.hub.NetworkClaim;
import org.shalim.hub.NetworkClaimService;
import org.shalim.ml.ModelPin;
import org.shalim.testing.Check;

/** The real IP transport, over loopback: UDP for queries, TCP for sessions. */
public final class LanTransportTest {

    private LanTransportTest() {
    }

    private static int freeUdpPort() throws Exception {
        try (DatagramSocket s = new DatagramSocket(0)) {
            return s.getLocalPort();
        }
    }

    public static void testClaimQueryAndReplicaSyncOverLoopback() throws Exception {
        int udpHub = freeUdpPort();
        int udpDevice = freeUdpPort();
        LanTransport hubT = new LanTransport(0, udpHub, List.of(new InetSocketAddress("127.0.0.1", udpDevice)),
                false, Clock.systemUTC()).start();
        LanTransport devT = new LanTransport(0, udpDevice, List.of(new InetSocketAddress("127.0.0.1", udpHub)),
                false, Clock.systemUTC()).start();
        try {
            SoftwareSigner key = SoftwareSigner.generate();
            byte[] salt = Bytes.random(32);
            String ap = "00:11:22:33:44:01";
            NetworkClaim claim = NetworkClaimService.createClaim(List.of(ap), salt, key, Instant.now());
            HubNetwork network = new HubNetwork("hub", "Lib", claim.getSaltedBssidHashes(), true, true, true);
            network.setClaim(claim);
            Hub hubA = new Hub("hub", "Lib", null, null, network, null);
            for (int i = 0; i < 20; i++) {
                hubA.getLog().append(HubLog.EventType.SYNC_COMPLETED, "a", null, "n" + i, key, Instant.now());
            }
            ModelPin pin = new ModelPin(ModelPin.Purpose.CENSOR, "c", "1", Hashing.sha256Hex("w"), "cpu", "int8");
            new SyncService("hub", List.of(hubT), key, null, Clock.systemUTC()).withCensorPin(pin).serve(hubA)
                    .answeringClaims(new NetworkClaimService(hubA), key, salt).attach();

            // A second instance of the same hub, on another "machine".
            Hub hubB = new Hub("hub", "Lib", null, null, null, null);
            SyncService b = new SyncService("hub", List.of(devT), key, null, Clock.systemUTC())
                    .withCensorPin(pin).serve(hubB).withTimeout(Duration.ofSeconds(5));
            ClaimQueryClient claims = new ClaimQueryClient(devT);
            FrameRouter.on(devT).add(b).add(claims);

            Check.isTrue(claims.confirmAttached(key.fingerprint(), ap, Duration.ofMillis(600)),
                    "UDP query out, TCP answer back");
            PeerEndpoint hubPeer = devT.peerAt("127.0.0.1", hubT.tcpPort());
            SyncService.SyncOutcome out = b.syncWith(hubPeer, hubB, SyncService.Job.FULL_SYNC);
            Check.isTrue(out.isSucceeded(), "synced over TCP: " + out.getFailureReason());
            Check.equal(20, out.getEntriesReceived(), "all entries");
            Check.equal(hubA.getLog().getHeadHash(), hubB.getLog().getHeadHash(), "converged");
            Check.isFalse(devT.discoverPeers().isEmpty(), "the hub is now a known peer");
        } finally {
            hubT.close();
            devT.close();
        }
    }

    public static void testOversizedFramesAreRefused() throws Exception {
        LanTransport t = new LanTransport(0, freeUdpPort(), List.of(), false, Clock.systemUTC()).start();
        try {
            Check.isFalse(t.broadcast(new byte[TransportProfile.WIFI_MAX_BROADCAST + 1]), "broadcast cap");
            Check.isFalse(t.send(t.peerAt("127.0.0.1", 1), new byte[TransportProfile.WIFI_MAX_FRAME + 1]),
                    "frame cap");
        } finally {
            t.close();
        }
    }
}
