package org.shalim.transport;

import java.util.ArrayList;
import java.util.List;
import org.shalim.crypto.Ed25519;
import org.shalim.hub.ClaimAnswer;
import org.shalim.hub.NetworkClaim;

/**
 * Wire forms of claim queries and answers. Both travel in the clear on the
 * local network. The query names only an access point the asker is already
 * attached to, and the answer is built to be safe for anyone on the network
 * to see (see {@link ClaimAnswer}).
 *
 * <pre>
 *   CLAIM_QUERY  ‖ nonce(32) ‖ bssid
 *   CLAIM_ANSWER ‖ nonce(32) ‖ hubKey(32) ‖ claimId ‖ claimedAt ‖ supersedes
 *                ‖ n ‖ n × (witnessKey, witnessedAt, signature(64)) ‖ signature(64)
 * </pre>
 */
public final class ClaimFrames {

    public static final int NONCE_BYTES = 32;
    /** Enough witnesses to judge age; more is padding a displacer could hide behind. */
    public static final int MAX_WITNESSES = 8;

    private ClaimFrames() {
    }

    public record Query(byte[] nonce, String bssid) {
    }

    public record Answer(byte[] nonce, ClaimAnswer answer) {
    }

    public static byte[] query(byte[] nonce, String bssid) {
        return Wire.writer().u8(MessageType.CLAIM_QUERY).fixed(nonce, NONCE_BYTES).smallString(bssid).done();
    }

    public static Query readQuery(byte[] frame) {
        Wire.Reader r = Wire.reader(frame);
        if (r.u8() != MessageType.CLAIM_QUERY) {
            throw new Wire.WireException("not a claim query");
        }
        Query q = new Query(r.fixed(NONCE_BYTES), r.smallString());
        r.end();
        return q;
    }

    public static byte[] answer(byte[] nonce, ClaimAnswer a) {
        List<NetworkClaim.Witness> witnesses = a.getWitnesses();
        int n = Math.min(witnesses.size(), MAX_WITNESSES);
        Wire.Writer w = Wire.writer().u8(MessageType.CLAIM_ANSWER).fixed(nonce, NONCE_BYTES)
                .fixed(a.getHubPublicKey(), Ed25519.PUBLIC_KEY_BYTES)
                .smallString(a.getClaimId()).instant(a.getClaimedAt()).smallString(a.getSupersedesClaimId())
                .u8(n);
        for (int i = 0; i < n; i++) {
            NetworkClaim.Witness wi = witnesses.get(i);
            w.hex(wi.peerKeyFingerprint()).instant(wi.witnessedAt()).fixed(wi.signature(), Ed25519.SIGNATURE_BYTES);
        }
        return w.fixed(a.getSignature(), Ed25519.SIGNATURE_BYTES).done();
    }

    public static Answer readAnswer(byte[] frame) {
        Wire.Reader r = Wire.reader(frame);
        if (r.u8() != MessageType.CLAIM_ANSWER) {
            throw new Wire.WireException("not a claim answer");
        }
        byte[] nonce = r.fixed(NONCE_BYTES);
        byte[] hubKey = r.fixed(Ed25519.PUBLIC_KEY_BYTES);
        String claimId = r.smallString();
        java.time.Instant claimedAt = r.instant();
        String supersedes = r.smallString();
        int n = r.u8();
        if (n > MAX_WITNESSES) {
            throw new Wire.WireException("too many witnesses");
        }
        List<NetworkClaim.Witness> witnesses = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            String fp = r.hex();
            java.time.Instant at = r.instant();
            byte[] sig = r.fixed(Ed25519.SIGNATURE_BYTES);
            if (fp == null || at == null) {
                throw new Wire.WireException("incomplete witness");
            }
            witnesses.add(new NetworkClaim.Witness(fp, at, sig));
        }
        byte[] sig = r.fixed(Ed25519.SIGNATURE_BYTES);
        r.end();
        return new Answer(nonce, new ClaimAnswer(hubKey, claimId, claimedAt, supersedes, witnesses, sig));
    }
}
