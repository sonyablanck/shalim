package org.shalim.trust;

import java.time.LocalDate;
import java.util.List;
import org.shalim.crypto.Signer;

/**
 * The seam where the anonymous-credential scheme (BBS with blind issuance,
 * hidden attributes, predicates and per-context pseudonyms) plugs in.
 *
 * <p>Everything around the credential is real code from stage 4: who is
 * issued one and when, daily expiry, the attributes, the pseudonyms and the
 * nullifier arithmetic, the registry, and every eligibility rule. The
 * signature and the zero-knowledge proof are not, because the scheme has not
 * been chosen (README open question 18) and it will be an audited library
 * bound over JNI, not hand-written here.
 *
 * <p><strong>There is deliberately no implementation in the main source
 * tree</strong>, exactly as with {@link org.shalim.skills.SkillCredentialScheme}.
 * The tests use a stand-in that reveals the member's secret in the open, which
 * names the prober to the target: the very thing this design exists to
 * prevent. So with no scheme bound, no credential is issued, no proof is
 * presented, no prober is accepted, and no link can be set up. Decided 19
 * November 2026: fail closed.
 */
public interface MemberCredentialScheme {

    /**
     * Signs today's credential over the attributes and a commitment to the
     * member's hidden secret (blind issuance: the issuer never sees the secret).
     */
    byte[] issue(Signer issuerKey, String hubKeyFingerprint, MemberCredential.RoleClass roleClass,
                 int joinedWeek, boolean attested, LocalDate epoch, String secretCommitment);

    /**
     * Proves possession of the credential, disclosing hub, role class and
     * epoch; proving {@code attested == true} and
     * {@code joinedWeek <= maxJoinedWeek} without disclosing either; and binding
     * {@code boundValues} (the two pseudonyms and the nullifier share) to the
     * same hidden secret. Null if the credential cannot satisfy the predicates.
     */
    byte[] prove(MemberCredential credential, byte[] memberSecret, int maxJoinedWeek, byte[] challenge,
                 List<byte[]> boundValues);

    /** Verifies a proof against the issuing hub's public key. */
    boolean verify(byte[] proof, byte[] issuerPublicKey, String hubKeyFingerprint, LocalDate epoch,
                   int maxJoinedWeek, byte[] challenge, List<byte[]> boundValues);
}
