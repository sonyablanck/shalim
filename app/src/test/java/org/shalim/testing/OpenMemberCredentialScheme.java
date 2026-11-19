package org.shalim.testing;

import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.shalim.crypto.Bytes;
import org.shalim.crypto.Canonical;
import org.shalim.crypto.Ed25519;
import org.shalim.crypto.Signer;
import org.shalim.trust.EpochNullifier;
import org.shalim.trust.MemberCredential;
import org.shalim.trust.MemberCredentialScheme;

/**
 * FOR TESTS ONLY. Signs credentials in the open and "proves" by handing the
 * verifier the member's secret through an in-memory side table. It names the
 * prober to the target, which is exactly what the real scheme must never do,
 * and is why nothing like it is in the main source tree.
 */
public final class OpenMemberCredentialScheme implements MemberCredentialScheme {

    private record Shown(byte[] signature, int joinedWeek, boolean attested, byte[] secret) {
    }

    private final Map<String, Shown> shown = new ConcurrentHashMap<>();

    private static byte[] payload(String hub, MemberCredential.RoleClass rc, int week, boolean attested,
                                  LocalDate epoch, String commitment) {
        return Canonical.of("test.member.credential").hex(hub).enumName(rc).u64(week).bool(attested).date(epoch)
                .hex(commitment).encode();
    }

    @Override
    public byte[] issue(Signer issuerKey, String hub, MemberCredential.RoleClass rc, int joinedWeek, boolean attested,
                        LocalDate epoch, String commitment) {
        return issuerKey.sign(payload(hub, rc, joinedWeek, attested, epoch, commitment));
    }

    @Override
    public byte[] prove(MemberCredential c, byte[] secret, int maxJoinedWeek, byte[] challenge,
                        List<byte[]> bound) {
        if (!c.isAttested() || c.getJoinedWeek() > maxJoinedWeek) {
            return null; // a proof of a false predicate cannot be made
        }
        byte[] id = Bytes.random(16);
        shown.put(Bytes.hex(id), new Shown(c.getSignature(), c.getJoinedWeek(), c.isAttested(), secret.clone()));
        return id;
    }

    @Override
    public boolean verify(byte[] proof, byte[] issuerPublicKey, String hub, LocalDate epoch, int maxJoinedWeek,
                          byte[] challenge, List<byte[]> bound) {
        Shown s = proof == null ? null : shown.get(Bytes.hex(proof));
        if (s == null || !s.attested() || s.joinedWeek() > maxJoinedWeek) {
            return false;
        }
        String commitment = EpochNullifier.commitment(s.secret());
        if (!Ed25519.verify(issuerPublicKey, payload(hub, MemberCredential.RoleClass.ORDINARY, s.joinedWeek(),
                s.attested(), epoch, commitment), s.signature())) {
            return false;
        }
        EpochNullifier n = EpochNullifier.derive(s.secret(), hub, epoch, challenge);
        return Bytes.equal(bound.get(1), Bytes.fromHex(MemberCredential.proberPseudonym(s.secret(), hub)))
                && Bytes.equal(bound.get(2), Bytes.fromHex(n.getNullifier()))
                && Bytes.equal(bound.get(3), n.getShareX()) && Bytes.equal(bound.get(4), n.getShareY());
    }
}
