package org.shalim.trust;

import java.time.Instant;
import java.time.LocalDate;
import java.util.List;

/**
 * The target hub's side of {@link MemberCredential}: issues every ordinary
 * member a fresh credential each day, and holds the commitments to members'
 * secrets so a double-spent {@link EpochNullifier} can be traced back.
 *
 * <p>Issuance is automatic and uniform. A hub that issued credentials only on
 * request would learn who asks, which is who probes.
 */
public class MemberCredentialIssuer {

    private String hubKeyFingerprint;

    /**
     * Commitment to each ordinary member's secret, made at join and bound to
     * their membership. The only link between a secret and a person, and it is
     * used only by {@link NullifierRegistry#trace}.
     */
    private List<String> secretCommitments;

    public MemberCredentialIssuer() {
        // TODO: pseudo-code
    }

    public MemberCredentialIssuer(String hubKeyFingerprint) {
        // TODO: pseudo-code
    }

    /**
     * Records a new member's secret commitment at join, and checks a device
     * attestation if the member's app offers one. Offering is automatic on
     * devices that support it; members whose devices cannot attest are
     * members exactly as before, and simply cannot act as probers here.
     */
    public boolean enrol(String userId, byte[] secretCommitment, List<byte[]> attestationChain,
                         byte[] challenge, Instant now) {
        // PSEUDO-CODE
        // attested = attestationChain non-empty
        //            AND DeviceBinding.verifyAttestation(chain, challenge, member key, ...)
        // store (membershipId -> secretCommitment, attested, joinedWeek)
        // RETURN true
        //    // Attestation moved here from link setup. At link setup it named the
        //    // prober; here it is one of many members' routine joins.
        return false;
    }

    /**
     * Issues today's credential to one member on sync. Called for every
     * MEMBER and MODERATOR, never for ADMIN or GUEST.
     */
    public MemberCredential issue(String userId, org.shalim.hub.Roster roster, LocalDate today) {
        // PSEUDO-CODE
        // m = roster.membershipOf(userId)
        // IF m absent OR m.baseRole NOT IN (MEMBER, MODERATOR) -> RETURN null
        //    // Base role, not effective role: a restricted admin is still an admin.
        // RETURN BBS.blindSign(attributes = { hub, ORDINARY, joinedWeek, attested,
        //                                     epoch = today },
        //                      committedSecret = commitment for m)
        return null;
    }

    /**
     * Size of the set a prober hides in: ordinary, attested members old
     * enough to present. Published to linked auditors as a coarse band only.
     */
    public int anonymitySetSize(org.shalim.hub.Roster roster, int minMembershipDays, LocalDate today) {
        // TODO: pseudo-code
        return 0;
    }

    public String getHubKeyFingerprint() {
        return hubKeyFingerprint;
    }
}
