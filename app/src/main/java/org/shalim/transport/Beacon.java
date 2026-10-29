package org.shalim.transport;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import org.shalim.crypto.Aead;
import org.shalim.crypto.Bytes;
import org.shalim.crypto.Canonical;
import org.shalim.crypto.CryptoException;
import org.shalim.crypto.Hkdf;
import org.shalim.crypto.Prf;

/**
 * "I exist, here's my log head", said so that only the hub's own replicas
 * can tell who is speaking.
 *
 * <p>The pseudo-code had beacons carry the hub's identity and log head in
 * the clear. On LoRa or Bluetooth that broadcasts the hub's existence to
 * anyone listening. Worse, the head changes every time anything happens, so
 * it is an activity meter. So:
 * <pre>
 *   epoch  = minutes since 1970 / 15
 *   token  = HMAC(beaconKey, epoch)[0..16)          rolls every 15 minutes
 *   frame  = BEACON ‖ epoch(4) ‖ token(16) ‖ Aead(k, head, aad = header)
 * </pre>
 * A holder of {@code beaconKey} recognises the token and reads the head. To
 * anyone else, a beacon is a type byte, an epoch number and 77 random-looking
 * bytes. Its token changes every quarter-hour, so beacons from different
 * epochs cannot be linked. The
 * radio transmission itself is still visible, and direction-finding still
 * locates it. Nothing in the payload can hide that.
 *
 * <p>82 bytes fits LoRa at SF9 or faster.
 */
public final class Beacon {

    public static final long EPOCH_SECONDS = 15 * 60;
    public static final int SIZE = 1 + 4 + 16 + 1 + 12 + 32 + 16;

    private Beacon() {
    }

    /** What this beacon told a key holder. */
    public record Sighting(String logHead, Instant epochStart) {
    }

    /** Derives the beacon key from a hub-replica secret, so it is never the secret itself. */
    public static byte[] keyFrom(byte[] replicaSecret) {
        return Hkdf.derive(null, replicaSecret, "shalim.beacon.key.v1".getBytes(StandardCharsets.US_ASCII), 32);
    }

    public static byte[] create(byte[] beaconKey, String logHead, Instant now) {
        long epoch = epoch(now);
        byte[] header = Wire.writer().u8(MessageType.BEACON).u32(epoch).fixed(token(beaconKey, epoch), 16).done();
        byte[] head = logHead == null ? new byte[32] : Bytes.fromHex(logHead);
        if (head.length != 32) {
            throw new IllegalArgumentException("log head must be a SHA-256 hash");
        }
        return Bytes.concat(header, Aead.seal(aeadKey(beaconKey), head, header));
    }

    /**
     * Recognises a beacon from a holder of the same key: current, previous or
     * next epoch, to absorb clock drift. Null for anyone else's beacon or a
     * malformed one. An all-zero head means the sender's log is empty.
     */
    public static Sighting recognise(byte[] frame, byte[] beaconKey, Instant now) {
        if (frame == null || frame.length != SIZE || (frame[0] & 0xff) != MessageType.BEACON) {
            return null;
        }
        Wire.Reader r = Wire.reader(frame);
        r.u8();
        long epoch = r.u32();
        byte[] token = r.fixed(16);
        long current = epoch(now);
        if (Math.abs(epoch - current) > 1 || !Bytes.equal(token, token(beaconKey, epoch))) {
            return null;
        }
        byte[] header = new byte[1 + 4 + 16];
        System.arraycopy(frame, 0, header, 0, header.length);
        byte[] sealed = r.fixed(r.remaining());
        try {
            byte[] head = Aead.open(aeadKey(beaconKey), sealed, header);
            boolean empty = true;
            for (byte b : head) {
                empty &= b == 0;
            }
            return new Sighting(empty ? null : Bytes.hex(head), Instant.ofEpochSecond(epoch * EPOCH_SECONDS));
        } catch (CryptoException e) {
            return null;
        }
    }

    static long epoch(Instant now) {
        return Math.floorDiv(now.getEpochSecond(), EPOCH_SECONDS) & 0xffffffffL;
    }

    private static byte[] token(byte[] beaconKey, long epoch) {
        byte[] mac = Prf.hmac(beaconKey, Canonical.of("shalim.beacon.token.v1").u64(epoch).encode());
        byte[] t = new byte[16];
        System.arraycopy(mac, 0, t, 0, 16);
        return t;
    }

    private static byte[] aeadKey(byte[] beaconKey) {
        return Hkdf.derive(null, beaconKey, "shalim.beacon.aead.v1".getBytes(StandardCharsets.US_ASCII), 32);
    }
}
