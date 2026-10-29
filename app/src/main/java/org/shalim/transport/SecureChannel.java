package org.shalim.transport;

import java.security.KeyPair;
import java.util.function.Predicate;
import org.shalim.crypto.Aead;
import org.shalim.crypto.Bytes;
import org.shalim.crypto.Canonical;
import org.shalim.crypto.CryptoException;
import org.shalim.crypto.Ed25519;
import org.shalim.crypto.Fingerprints;
import org.shalim.crypto.Hashing;
import org.shalim.crypto.Hkdf;
import org.shalim.crypto.Signer;
import org.shalim.crypto.X25519;

/**
 * Mutually authenticated, encrypted sessions between two devices, over any
 * transport. "Must pass before any hub data is exchanged" ({@link PeerEndpoint}).
 *
 * <h2>Handshake</h2>
 *
 * <p>SIGMA-I (Krawczyk 2003), the pattern behind the TLS 1.3 and IKEv2
 * handshakes, built from the stage 1 primitives. Three messages:
 * <pre>
 *   1  I → R   sid, eI
 *   2  R → I   sid, eR, AEAD(kR, R ‖ Sig_R(H(msg1, eR, R)))
 *   3  I → R   sid,     AEAD(kI, I ‖ Sig_I(H(msg1, msg2, I)))
 * </pre>
 * Here eI and eR are fresh X25519 keys; R and I are the parties' long-term
 * Ed25519 keys; kR and kI come from HKDF over X25519(eI, eR) and the
 * transcript. Data keys come from HKDF over the same secret and all three
 * messages, one key per direction.
 *
 * <ul>
 *   <li><b>Authentication:</b> each side signs a transcript that includes both
 *       ephemeral keys, so a signature is good for this session only.</li>
 *   <li><b>Forward secrecy:</b> ephemeral keys are discarded after the
 *       handshake. A long-term key stolen later decrypts nothing recorded.</li>
 *   <li><b>Identity protection:</b> both identities travel encrypted. The
 *       initiator's is revealed only after it has verified the responder, so an
 *       active attacker who answers in the responder's place learns nothing
 *       about who was connecting. The responder's identity can be learnt by
 *       anyone who initiates. Hubs are responders; members' devices are
 *       initiators. That is the right way round.</li>
 *   <li><b>Sizes:</b> 41, 153 and 121 bytes, so a handshake fits LoRa at SF7
 *       or SF8, though it costs three frames of duty cycle.</li>
 * </ul>
 *
 * <h2>Data</h2>
 *
 * <p>{@code SEALED ‖ sid(8) ‖ counter(8) ‖ ChaCha20-Poly1305(k_dir, nonce =
 * 0⁴ ‖ counter, aad = header)}. That is 33 bytes of overhead per frame.
 * Counters start at zero and never repeat for a key. Incoming counters
 * are checked against a 64-frame sliding window, as in IPsec, so a replayed
 * frame is refused but frames that arrive out of order over a mesh are not.
 */
public final class SecureChannel {

    public static final int SESSION_ID_BYTES = 8;
    private static final int SIG = Ed25519.SIGNATURE_BYTES;
    private static final int PUB = Ed25519.PUBLIC_KEY_BYTES;
    private static final byte[] ZERO_NONCE = new byte[12];

    private SecureChannel() {
    }

    /** The handshake or a sealed frame failed. The frame is dropped and the session is not established. */
    public static final class ChannelException extends Exception {
        private static final long serialVersionUID = 1L;

        public ChannelException(String message) {
            super(message);
        }
    }

    /** Session id of any handshake or sealed frame; null if the frame is too short. */
    public static byte[] sessionIdOf(byte[] frame) {
        if (frame == null || frame.length < 1 + SESSION_ID_BYTES) {
            return null;
        }
        byte[] sid = new byte[SESSION_ID_BYTES];
        System.arraycopy(frame, 1, sid, 0, SESSION_ID_BYTES);
        return sid;
    }

    // --- initiator --------------------------------------------------------

    public static Initiator initiate(Signer me, String expectedPeerFingerprint) {
        return new Initiator(me, expectedPeerFingerprint);
    }

    public static final class Initiator {
        private final Signer me;
        private final String expectedPeer;
        private final KeyPair ephemeral;
        private final byte[] sid;
        private final byte[] msg1;
        private byte[] msg3;

        private Initiator(Signer me, String expectedPeer) {
            this.me = me;
            this.expectedPeer = expectedPeer;
            this.ephemeral = X25519.generate();
            this.sid = Bytes.random(SESSION_ID_BYTES);
            this.msg1 = Wire.writer().u8(MessageType.HANDSHAKE_1).fixed(sid, SESSION_ID_BYTES)
                    .fixed(X25519.rawPublicKey(ephemeral.getPublic()), X25519.KEY_BYTES).done();
        }

        public byte[] firstMessage() {
            return msg1.clone();
        }

        public byte[] sessionId() {
            return sid.clone();
        }

        /**
         * Processes message 2. On success, {@link #finalMessage()} is message 3
         * and the returned session is ready.
         */
        public Session onResponse(byte[] msg2) throws ChannelException {
            if (msg2 == null || msg2.length != 1 + SESSION_ID_BYTES + X25519.KEY_BYTES + PUB + SIG + 16
                    || msg2[0] != MessageType.HANDSHAKE_2 || !Bytes.equal(sessionIdOf(msg2), sid)) {
                throw new ChannelException("malformed handshake 2");
            }
            byte[] eR = slice(msg2, 1 + SESSION_ID_BYTES, X25519.KEY_BYTES);
            byte[] header2 = slice(msg2, 0, 1 + SESSION_ID_BYTES + X25519.KEY_BYTES);
            byte[] dh = agree(ephemeral, eR);
            byte[][] hs = handshakeKeys(dh, msg1, eR);
            byte[] body;
            try {
                body = Aead.openWithNonce(hs[0], ZERO_NONCE,
                        slice(msg2, header2.length, msg2.length - header2.length), Bytes.concat(msg1, header2));
            } catch (CryptoException e) {
                throw new ChannelException("handshake 2 did not authenticate");
            }
            byte[] rPub = slice(body, 0, PUB);
            byte[] rSig = slice(body, PUB, SIG);
            if (!Ed25519.verify(rPub, responderTranscript(msg1, eR, rPub), rSig)) {
                throw new ChannelException("responder signature invalid");
            }
            String rFp = Fingerprints.signingKey(rPub);
            if (expectedPeer != null && !expectedPeer.equals(rFp)) {
                throw new ChannelException("responder is not the expected peer");
            }
            // Only now, with the responder verified, reveal who we are.
            byte[] myPub = me.publicKey();
            byte[] mySig = me.sign(initiatorTranscript(msg1, msg2, myPub));
            byte[] header3 = Wire.writer().u8(MessageType.HANDSHAKE_3).fixed(sid, SESSION_ID_BYTES).done();
            byte[] sealed = Aead.sealWithNonce(hs[1], ZERO_NONCE, Bytes.concat(myPub, mySig),
                    Bytes.concat(msg1, msg2, header3));
            msg3 = Bytes.concat(header3, sealed);
            byte[][] data = dataKeys(dh, msg1, msg2, msg3);
            Bytes.wipe(dh);
            return new Session(sid, rPub, true, data[0], data[1]);
        }

        public byte[] finalMessage() {
            return msg3 == null ? null : msg3.clone();
        }
    }

    // --- responder --------------------------------------------------------

    public static final class Responder {
        private final byte[] sid;
        private final byte[] msg1;
        private final byte[] msg2;
        private final byte[] dh;
        private final byte[] kI;

        /** Processes message 1 and prepares message 2. */
        public static Responder accept(byte[] msg1, Signer me) throws ChannelException {
            if (msg1 == null || msg1.length != 1 + SESSION_ID_BYTES + X25519.KEY_BYTES
                    || msg1[0] != MessageType.HANDSHAKE_1) {
                throw new ChannelException("malformed handshake 1");
            }
            return new Responder(msg1.clone(), me);
        }

        private Responder(byte[] msg1, Signer me) throws ChannelException {
            this.msg1 = msg1;
            this.sid = sessionIdOf(msg1);
            byte[] eI = slice(msg1, 1 + SESSION_ID_BYTES, X25519.KEY_BYTES);
            KeyPair ephemeral = X25519.generate();
            byte[] eR = X25519.rawPublicKey(ephemeral.getPublic());
            this.dh = agree(ephemeral, eI);
            byte[][] hs = handshakeKeys(dh, msg1, eR);
            this.kI = hs[1];
            byte[] myPub = me.publicKey();
            byte[] mySig = me.sign(responderTranscript(msg1, eR, myPub));
            byte[] header2 = Wire.writer().u8(MessageType.HANDSHAKE_2).fixed(sid, SESSION_ID_BYTES)
                    .fixed(eR, X25519.KEY_BYTES).done();
            byte[] sealed = Aead.sealWithNonce(hs[0], ZERO_NONCE, Bytes.concat(myPub, mySig),
                    Bytes.concat(msg1, header2));
            this.msg2 = Bytes.concat(header2, sealed);
        }

        public byte[] response() {
            return msg2.clone();
        }

        public byte[] sessionId() {
            return sid.clone();
        }

        /**
         * Processes message 3. {@code authorise} decides, by key fingerprint,
         * whether this initiator may hold a session here at all.
         */
        public Session onFinish(byte[] msg3, Predicate<String> authorise) throws ChannelException {
            if (msg3 == null || msg3.length != 1 + SESSION_ID_BYTES + PUB + SIG + 16
                    || msg3[0] != MessageType.HANDSHAKE_3 || !Bytes.equal(sessionIdOf(msg3), sid)) {
                throw new ChannelException("malformed handshake 3");
            }
            byte[] header3 = slice(msg3, 0, 1 + SESSION_ID_BYTES);
            byte[] body;
            try {
                body = Aead.openWithNonce(kI, ZERO_NONCE, slice(msg3, header3.length, msg3.length - header3.length),
                        Bytes.concat(msg1, msg2, header3));
            } catch (CryptoException e) {
                throw new ChannelException("handshake 3 did not authenticate");
            }
            byte[] iPub = slice(body, 0, PUB);
            byte[] iSig = slice(body, PUB, SIG);
            if (!Ed25519.verify(iPub, initiatorTranscript(msg1, msg2, iPub), iSig)) {
                throw new ChannelException("initiator signature invalid");
            }
            if (authorise != null && !authorise.test(Fingerprints.signingKey(iPub))) {
                throw new ChannelException("initiator not authorised here");
            }
            byte[][] data = dataKeys(dh, msg1, msg2, msg3);
            Bytes.wipe(dh);
            return new Session(sid, iPub, false, data[1], data[0]);
        }
    }

    // --- session ----------------------------------------------------------

    /** An established session. Thread-safe. */
    public static final class Session {
        private final byte[] sid;
        private final byte[] remotePublicKey;
        private final boolean initiator;
        private final byte[] sendKey;
        private final byte[] receiveKey;
        private long sendCounter;
        private long highestReceived = -1;
        private long window; // bit i set = (highestReceived - i) seen

        Session(byte[] sid, byte[] remotePublicKey, boolean initiator, byte[] sendKey, byte[] receiveKey) {
            this.sid = sid.clone();
            this.remotePublicKey = remotePublicKey.clone();
            this.initiator = initiator;
            this.sendKey = sendKey;
            this.receiveKey = receiveKey;
        }

        public synchronized byte[] seal(byte[] inner) {
            if (sendCounter == Long.MAX_VALUE) {
                throw new IllegalStateException("session exhausted; start a new one");
            }
            long counter = sendCounter++;
            byte[] header = header(counter);
            return Bytes.concat(header, Aead.sealWithNonce(sendKey, nonce(counter), inner, header));
        }

        public synchronized byte[] open(byte[] frame) throws ChannelException {
            if (frame == null || frame.length < 1 + SESSION_ID_BYTES + 8 + 16
                    || frame[0] != MessageType.SEALED || !Bytes.equal(sessionIdOf(frame), sid)) {
                throw new ChannelException("not a frame for this session");
            }
            Wire.Reader r = Wire.reader(frame);
            r.u8();
            r.fixed(SESSION_ID_BYTES);
            long counter = r.u64();
            if (counter < 0 || seen(counter)) {
                throw new ChannelException("replayed or stale frame");
            }
            byte[] header = slice(frame, 0, 1 + SESSION_ID_BYTES + 8);
            byte[] inner;
            try {
                inner = Aead.openWithNonce(receiveKey, nonce(counter),
                        slice(frame, header.length, frame.length - header.length), header);
            } catch (CryptoException e) {
                throw new ChannelException("frame did not authenticate");
            }
            mark(counter); // only after authentication, so forged counters cannot poison the window
            return inner;
        }

        private boolean seen(long counter) {
            if (counter > highestReceived) {
                return false;
            }
            long age = highestReceived - counter;
            return age >= 64 || (window & (1L << age)) != 0;
        }

        private void mark(long counter) {
            if (counter > highestReceived) {
                long shift = counter - highestReceived;
                window = shift >= 64 ? 0 : window << shift;
                window |= 1;
                highestReceived = counter;
            } else {
                window |= 1L << (highestReceived - counter);
            }
        }

        private byte[] header(long counter) {
            return Wire.writer().u8(MessageType.SEALED).fixed(sid, SESSION_ID_BYTES).u64(counter).done();
        }

        private static byte[] nonce(long counter) {
            byte[] n = new byte[12];
            for (int i = 0; i < 8; i++) {
                n[11 - i] = (byte) (counter >>> (8 * i));
            }
            return n;
        }

        public byte[] sessionId() {
            return sid.clone();
        }

        public byte[] remotePublicKey() {
            return remotePublicKey.clone();
        }

        public String remoteFingerprint() {
            return Fingerprints.signingKey(remotePublicKey);
        }

        public boolean isInitiator() {
            return initiator;
        }

        /** Per-frame overhead of {@link #seal}. */
        public static int overhead() {
            return 1 + SESSION_ID_BYTES + 8 + 16;
        }
    }

    // --- internals --------------------------------------------------------

    private static byte[] agree(KeyPair ephemeral, byte[] peerEphemeral) throws ChannelException {
        try {
            return X25519.agree(ephemeral.getPrivate(), peerEphemeral);
        } catch (CryptoException e) {
            throw new ChannelException("bad ephemeral key");
        }
    }

    /** [kR, kI]: keys for the responder's and the initiator's handshake messages. */
    private static byte[][] handshakeKeys(byte[] dh, byte[] msg1, byte[] eR) {
        byte[] okm = Hkdf.derive(Hashing.sha256(msg1, eR), dh,
                "shalim.channel.hs.v1".getBytes(java.nio.charset.StandardCharsets.US_ASCII), 64);
        return new byte[][] {slice(okm, 0, 32), slice(okm, 32, 32)};
    }

    /** [initiator→responder, responder→initiator]. */
    private static byte[][] dataKeys(byte[] dh, byte[] msg1, byte[] msg2, byte[] msg3) {
        byte[] okm = Hkdf.derive(Hashing.sha256(msg1, msg2, msg3), dh,
                "shalim.channel.data.v1".getBytes(java.nio.charset.StandardCharsets.US_ASCII), 64);
        return new byte[][] {slice(okm, 0, 32), slice(okm, 32, 32)};
    }

    private static byte[] responderTranscript(byte[] msg1, byte[] eR, byte[] rPub) {
        return Canonical.of("shalim.channel.sig.r.v1").bytes(msg1).bytes(eR).bytes(rPub).digest();
    }

    private static byte[] initiatorTranscript(byte[] msg1, byte[] msg2, byte[] iPub) {
        return Canonical.of("shalim.channel.sig.i.v1").bytes(msg1).bytes(msg2).bytes(iPub).digest();
    }

    private static byte[] slice(byte[] in, int from, int length) {
        byte[] out = new byte[length];
        System.arraycopy(in, from, out, 0, length);
        return out;
    }
}
