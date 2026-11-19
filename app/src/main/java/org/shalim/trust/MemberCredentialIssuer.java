package org.shalim.trust;

import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.shalim.crypto.Signer;
import org.shalim.hub.Roster;
import org.shalim.identity.Membership;
import org.shalim.identity.Role;

/**
 * The target hub's side of {@link MemberCredential}: issues every ordinary
 * member a fresh credential each day, and holds the commitments to members'
 * secrets so a double-spent {@link EpochNullifier} can be traced back.
 *
 * <p>Issuance is automatic and uniform. A hub that issued credentials only on
 * request would learn who asks, which is who probes.
 */
public class MemberCredentialIssuer {

    /**
     * Checks a device attestation chain at join. The real check (Play
     * Integrity / App Attest) arrives with device work in stage 7; with none
     * bound, nobody is attested, so nobody can act as a prober. Fails closed.
     */
    @FunctionalInterface
    public interface DeviceAttestationCheck {
        boolean verify(String userId, List<byte[]> attestationChain, byte[] challenge);
    }

    private record Enrolment(String membershipId, String secretCommitment, boolean attested) {
    }

    private final String hubKeyFingerprint;
    private final MemberCredentialScheme scheme;
    private final DeviceAttestationCheck attestationCheck;

    /** userId -> enrolment. The only link between a secret and a person. */
    private final Map<String, Enrolment> enrolments = new HashMap<>();

    public MemberCredentialIssuer(String hubKeyFingerprint, MemberCredentialScheme scheme,
                                  DeviceAttestationCheck attestationCheck) {
        this.hubKeyFingerprint = hubKeyFingerprint;
        this.scheme = scheme;
        this.attestationCheck = attestationCheck;
    }

    /**
     * Records a new member's secret commitment at join, and checks a device
     * attestation if the member's app offers one. Members whose devices cannot
     * attest are members exactly as before, and simply cannot act as probers.
     */
    public boolean enrol(String userId, String membershipId, String secretCommitment,
                         List<byte[]> attestationChain, byte[] challenge, Instant now) {
        if (userId == null || secretCommitment == null) {
            return false;
        }
        boolean attested = attestationChain != null && !attestationChain.isEmpty() && attestationCheck != null
                && attestationCheck.verify(userId, attestationChain, challenge);
        enrolments.put(userId, new Enrolment(membershipId, secretCommitment, attested));
        return true;
    }

    /**
     * Issues today's credential to one member on sync. Called for every
     * MEMBER and MODERATOR, never for ADMIN or GUEST. Null without a scheme.
     */
    public MemberCredential issue(String userId, Roster roster, Signer issuerKey, LocalDate today) {
        if (scheme == null || issuerKey == null) {
            return null;
        }
        Membership m = roster.membershipOf(userId).orElse(null);
        // Base role, not effective role: a restricted admin is still an admin.
        if (m == null || (m.getRole() != Role.MEMBER && m.getRole() != Role.MODERATOR)) {
            return null;
        }
        Enrolment e = enrolments.get(userId);
        if (e == null) {
            return null;
        }
        int joinedWeek = MemberCredential.weekOf(LocalDate.ofInstant(m.getJoinedAt(), ZoneOffset.UTC));
        byte[] sig = scheme.issue(issuerKey, hubKeyFingerprint, MemberCredential.RoleClass.ORDINARY, joinedWeek,
                e.attested(), today, e.secretCommitment());
        return sig == null ? null : new MemberCredential(hubKeyFingerprint, MemberCredential.RoleClass.ORDINARY,
                joinedWeek, e.attested(), today, sig);
    }

    /**
     * Size of the set a prober hides in: ordinary, attested, enrolled members
     * old enough to present.
     */
    public int anonymitySetSize(Roster roster, int minMembershipDays, LocalDate today) {
        int maxWeek = MemberCredential.maxJoinedWeek(today, minMembershipDays);
        int n = 0;
        for (Membership m : roster.getMemberships()) {
            Enrolment e = enrolments.get(m.getUserId());
            if (e == null || !e.attested() || (m.getRole() != Role.MEMBER && m.getRole() != Role.MODERATOR)) {
                continue;
            }
            if (MemberCredential.weekOf(LocalDate.ofInstant(m.getJoinedAt(), ZoneOffset.UTC)) <= maxWeek) {
                n++;
            }
        }
        return n;
    }

    /** The membership a recovered secret belongs to. Used only by {@link NullifierRegistry#trace}. */
    String membershipForCommitment(String commitment) {
        for (Enrolment e : enrolments.values()) {
            if (e.secretCommitment().equals(commitment)) {
                return e.membershipId();
            }
        }
        return null;
    }

    /** Called when a member leaves: their commitment goes with them. */
    public void forget(String userId) {
        enrolments.remove(userId);
    }

    public boolean isEnrolled(String userId) {
        return enrolments.containsKey(userId);
    }

    public MemberCredentialScheme getScheme() {
        return scheme;
    }

    public String getHubKeyFingerprint() {
        return hubKeyFingerprint;
    }
}
