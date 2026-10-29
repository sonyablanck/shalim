package org.shalim.transport;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.shalim.crypto.Bytes;
import org.shalim.crypto.SoftwareSigner;
import org.shalim.hub.HubLog;
import org.shalim.testing.Check;

/** The secure channel, the wire codec, beacons and airtime. */
public final class ChannelAndWireTest {

    private static final Instant NOW = Instant.parse("2026-10-29T09:00:00Z");

    private ChannelAndWireTest() {
    }

    private static SecureChannel.Session[] pair(SoftwareSigner i, SoftwareSigner r) throws Exception {
        SecureChannel.Initiator init = SecureChannel.initiate(i, null);
        byte[] m1 = init.firstMessage();
        SecureChannel.Responder resp = SecureChannel.Responder.accept(m1, r);
        SecureChannel.Session si = init.onResponse(resp.response());
        SecureChannel.Session sr = resp.onFinish(init.finalMessage(), fp -> true);
        return new SecureChannel.Session[] {si, sr};
    }

    public static void testHandshakeAuthenticatesBothSidesAndFitsLoRa() throws Exception {
        SoftwareSigner a = SoftwareSigner.generate();
        SoftwareSigner b = SoftwareSigner.generate();
        SecureChannel.Initiator init = SecureChannel.initiate(a, b.fingerprint());
        SecureChannel.Responder resp = SecureChannel.Responder.accept(init.firstMessage(), b);
        SecureChannel.Session si = init.onResponse(resp.response());
        SecureChannel.Session sr = resp.onFinish(init.finalMessage(), fp -> fp.equals(a.fingerprint()));
        Check.equal(b.fingerprint(), si.remoteFingerprint(), "initiator learns responder");
        Check.equal(a.fingerprint(), sr.remoteFingerprint(), "responder learns initiator");
        Check.equal(41, init.firstMessage().length, "message 1");
        Check.equal(153, resp.response().length, "message 2");
        Check.equal(121, init.finalMessage().length, "message 3");
        Check.isTrue(resp.response().length <= LoRaAirtime.maxPayload(8), "largest message fits LoRa SF8");
        byte[] frame = si.seal("hello".getBytes(StandardCharsets.UTF_8));
        Check.equal("hello", new String(sr.open(frame), StandardCharsets.UTF_8), "data flows");
        Check.equal("back", new String(si.open(sr.seal("back".getBytes(StandardCharsets.UTF_8))),
                StandardCharsets.UTF_8), "both ways");
    }

    public static void testIdentitiesAreNotInTheClear() throws Exception {
        SoftwareSigner a = SoftwareSigner.generate();
        SoftwareSigner b = SoftwareSigner.generate();
        SecureChannel.Initiator init = SecureChannel.initiate(a, null);
        SecureChannel.Responder resp = SecureChannel.Responder.accept(init.firstMessage(), b);
        init.onResponse(resp.response());
        byte[] wire = Bytes.concat(init.firstMessage(), resp.response(), init.finalMessage());
        String hex = Bytes.hex(wire);
        Check.isFalse(hex.contains(Bytes.hex(a.publicKey())), "initiator key hidden");
        Check.isFalse(hex.contains(Bytes.hex(b.publicKey())), "responder key hidden from passive observers");
    }

    public static void testWrongResponderAndUnauthorisedInitiatorAreRefused() throws Exception {
        SoftwareSigner a = SoftwareSigner.generate();
        SoftwareSigner b = SoftwareSigner.generate();
        SecureChannel.Initiator pinned = SecureChannel.initiate(a, SoftwareSigner.generate().fingerprint());
        SecureChannel.Responder r1 = SecureChannel.Responder.accept(pinned.firstMessage(), b);
        boolean pinnedRefused = false;
        try {
            pinned.onResponse(r1.response());
        } catch (SecureChannel.ChannelException e) {
            pinnedRefused = true;
        }
        Check.isTrue(pinnedRefused, "pinned initiator refuses an unexpected responder");
        Check.isNull(pinned.finalMessage(), "and never reveals its identity");

        SecureChannel.Initiator init = SecureChannel.initiate(a, null);
        SecureChannel.Responder r2 = SecureChannel.Responder.accept(init.firstMessage(), b);
        init.onResponse(r2.response());
        boolean refused = false;
        try {
            r2.onFinish(init.finalMessage(), fp -> false);
        } catch (SecureChannel.ChannelException e) {
            refused = true;
        }
        Check.isTrue(refused, "responder refuses an unauthorised initiator");
    }

    public static void testTamperedHandshakeFails() throws Exception {
        SoftwareSigner a = SoftwareSigner.generate();
        SoftwareSigner b = SoftwareSigner.generate();
        SecureChannel.Initiator init = SecureChannel.initiate(a, null);
        SecureChannel.Responder resp = SecureChannel.Responder.accept(init.firstMessage(), b);
        byte[] m2 = resp.response();
        m2[60] ^= 1;
        boolean failed = false;
        try {
            init.onResponse(m2);
        } catch (SecureChannel.ChannelException e) {
            failed = true;
        }
        Check.isTrue(failed, "flipped bit in message 2");
    }

    public static void testReplayWindow() throws Exception {
        SecureChannel.Session[] s = pair(SoftwareSigner.generate(), SoftwareSigner.generate());
        byte[] f0 = s[0].seal(new byte[] {0});
        byte[] f1 = s[0].seal(new byte[] {1});
        byte[] f2 = s[0].seal(new byte[] {2});
        Check.equalBytes(new byte[] {2}, s[1].open(f2), "newest first");
        Check.equalBytes(new byte[] {0}, s[1].open(f0), "older, out of order, accepted once");
        boolean replayed = false;
        try {
            s[1].open(f0);
        } catch (SecureChannel.ChannelException e) {
            replayed = true;
        }
        Check.isTrue(replayed, "replay refused");
        Check.equalBytes(new byte[] {1}, s[1].open(f1), "the gap still fills");
        byte[] forged = f2.clone();
        forged[forged.length - 1] ^= 1;
        boolean forgedRefused = false;
        try {
            s[1].open(forged);
        } catch (SecureChannel.ChannelException e) {
            forgedRefused = true;
        }
        Check.isTrue(forgedRefused, "forged frame refused");
        boolean otherSession = false;
        SecureChannel.Session[] t = pair(SoftwareSigner.generate(), SoftwareSigner.generate());
        try {
            t[1].open(s[0].seal(new byte[] {9}));
        } catch (SecureChannel.ChannelException e) {
            otherSession = true;
        }
        Check.isTrue(otherSession, "frames do not cross sessions");
    }

    public static void testWireRejectsMalformedInput() {
        byte[] good = Wire.writer().u8(1).small(new byte[] {1, 2}).bytes(new byte[3]).done();
        Wire.Reader r = Wire.reader(good);
        r.u8();
        r.small();
        r.bytes(10);
        r.end();
        Check.throwsA(Wire.WireException.class, () -> Wire.reader(new byte[] {1, 5, 0}).fixed(9), "truncated");
        Check.throwsA(Wire.WireException.class, () -> {
            Wire.Reader rr = Wire.reader(good);
            rr.u8();
            rr.small();
            rr.bytes(2);
        }, "over the length cap");
        Check.throwsA(Wire.WireException.class, () -> {
            Wire.Reader rr = Wire.reader(good);
            rr.u8();
            rr.end();
        }, "trailing bytes");
    }

    public static void testLogEntryRoundTrip() {
        SoftwareSigner hub = SoftwareSigner.generate();
        HubLog log = new HubLog("h");
        HubLog.Entry e = log.append(HubLog.EventType.ROLE_ASSIGNED, "a", "b", "MODERATOR", hub, NOW);
        Wire.Writer w = Wire.writer();
        LogEntryCodec.write(w, e);
        Wire.Reader r = Wire.reader(w.done());
        HubLog.Entry back = LogEntryCodec.read(r);
        r.end();
        HubLog replica = new HubLog("h");
        Check.equal(1, replica.mergeEntries(List.of(back), fp -> hub.publicKey()), "decoded entry verifies");
        Check.isTrue(LogEntryCodec.encodedSize(e) < TransportProfile.BLUETOOTH_MAX_FRAME - 40,
                "an entry fits a Bluetooth frame");
    }

    public static void testBeaconsAreRecognisedOnlyByKeyHolders() {
        byte[] key = Beacon.keyFrom(Bytes.random(32));
        String head = Bytes.hex(Bytes.random(32));
        byte[] beacon = Beacon.create(key, head, NOW);
        Check.equal(Beacon.SIZE, beacon.length, "fixed size");
        Check.isTrue(beacon.length <= LoRaAirtime.maxPayload(9), "fits LoRa SF9");
        Check.equal(head, Beacon.recognise(beacon, key, NOW).logHead(), "replica reads the head");
        Check.isNull(Beacon.recognise(beacon, Beacon.keyFrom(Bytes.random(32)), NOW), "outsider cannot");
        Check.isNull(Beacon.recognise(beacon, key, NOW.plus(Duration.ofHours(1))), "stale beacon ignored");
        byte[] later = Beacon.create(key, head, NOW.plus(Duration.ofMinutes(30)));
        Check.isFalse(Bytes.hex(later).substring(10, 42).equals(Bytes.hex(beacon).substring(10, 42)),
                "token rolls, so beacons from different epochs do not link");
        Check.isNull(Beacon.recognise(Beacon.create(key, null, NOW), key, NOW).logHead(), "empty log");
    }

    public static void testLoRaAirtimeAndDutyCycle() {
        double t = LoRaAirtime.seconds(10, 7);
        Check.isTrue(Math.abs(t - 0.041216) < 1e-6, "SF7 10 bytes = 41.2 ms, was " + t);
        Check.isTrue(LoRaAirtime.seconds(51, 12) > 2.0, "SF12 is slow");
        AirtimeBudget budget = AirtimeBudget.hourly(0.01);
        Check.isTrue(Math.abs(budget.remaining(NOW) - 36.0) < 1e-9, "36 s per hour at 1%");
        Check.isTrue(budget.trySpend(35.9, NOW), "within budget");
        Check.isFalse(budget.trySpend(0.2, NOW.plusSeconds(10)), "refused past the limit");
        Check.isTrue(budget.trySpend(0.2, NOW.plusSeconds(3601)), "window rolls");
    }
}
