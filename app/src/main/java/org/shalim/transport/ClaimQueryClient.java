package org.shalim.transport;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import org.shalim.crypto.Bytes;
import org.shalim.hub.ClaimAnswer;
import org.shalim.hub.NetworkClaimService;

/**
 * Device side of claim queries: asks the local network whether a hub claims
 * an access point, and collects the answers. This is the
 * {@link NetworkClaimService.ClaimProbe} behind the creation check. It is also
 * how a device confirms, on its own, that it is attached to a given hub's
 * network ({@link #confirmAttached}).
 *
 * <p>Register it on the transport, directly or through a {@link FrameRouter}.
 */
public final class ClaimQueryClient implements NetworkClaimService.ClaimProbe, Transport.FrameListener {

    /** Queries are repeated while listening, so a hub that was briefly busy is not missed. */
    public static final Duration REPEAT = Duration.ofSeconds(30);

    private final Transport transport;
    private final Map<String, List<ClaimAnswer>> collecting = new ConcurrentHashMap<>();

    public ClaimQueryClient(Transport transport) {
        this.transport = transport;
    }

    @Override
    public List<ClaimAnswer> ask(byte[] nonce, String bssid, Duration listen) {
        String key = Bytes.hex(nonce);
        List<ClaimAnswer> answers = new CopyOnWriteArrayList<>();
        collecting.put(key, answers);
        try {
            byte[] query = ClaimFrames.query(nonce, bssid);
            long deadline = System.nanoTime() + listen.toNanos();
            long repeat = Math.max(1, Math.min(REPEAT.toNanos(), listen.toNanos() / 3));
            while (true) {
                transport.broadcast(query);
                long left = deadline - System.nanoTime();
                if (left <= 0) {
                    break;
                }
                Thread.sleep(Math.max(1, Math.min(repeat, left) / 1_000_000));
                if (System.nanoTime() >= deadline) {
                    break;
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            collecting.remove(key);
        }
        return new ArrayList<>(answers);
    }

    /**
     * Whether the hub with this key answers for the access point this device
     * is on: the device's own proof of being attached to that hub's network.
     */
    public boolean confirmAttached(String hubKeyFingerprint, String attachedBssid, Duration listen) {
        byte[] nonce = Bytes.random(ClaimFrames.NONCE_BYTES);
        for (ClaimAnswer a : ask(nonce, attachedBssid, listen)) {
            if (a.hubKeyFingerprint().equals(hubKeyFingerprint) && a.verify(nonce, attachedBssid)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public void onFrame(PeerEndpoint from, byte[] payload) {
        if (payload.length == 0 || (payload[0] & 0xff) != MessageType.CLAIM_ANSWER) {
            return;
        }
        try {
            ClaimFrames.Answer a = ClaimFrames.readAnswer(payload);
            List<ClaimAnswer> list = collecting.get(Bytes.hex(a.nonce()));
            if (list != null && list.size() < 64) {
                list.add(a.answer());
            }
        } catch (Wire.WireException e) {
            // malformed; dropped
        }
    }
}
