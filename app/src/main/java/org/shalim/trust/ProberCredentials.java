package org.shalim.trust;

import java.time.LocalDate;
import java.util.HashMap;
import java.util.Map;

/**
 * The credentials on one member's device: one {@link MemberCredential} per hub
 * they are an ordinary member of, refreshed daily on sync whether or not they
 * ever probe. An admin carrying a link presents from here.
 *
 * <p>An honest client presents at most once per hub per day. A second
 * request on the same day re-sends the identical proof, which the target sees
 * as a harmless retransmission; a fresh proof with a new challenge would be a
 * double spend and would unmask the member.
 */
public final class ProberCredentials {

    private final MemberCredentialScheme scheme;
    private final Map<String, MemberCredential> byHub = new HashMap<>();
    private final Map<String, EligibilityProof> presentedToday = new HashMap<>();

    public ProberCredentials(MemberCredentialScheme scheme) {
        this.scheme = scheme;
    }

    /** Stores today's credential for a hub, replacing yesterday's. */
    public synchronized void store(MemberCredential credential) {
        if (credential != null) {
            byHub.put(credential.getHubKeyFingerprint(), credential);
        }
    }

    public synchronized EligibilityProof present(String targetKeyFingerprint, String auditorKeyFingerprint,
                                                 LocalDate today, int minMembershipDays, byte[] challenge) {
        EligibilityProof earlier = presentedToday.get(targetKeyFingerprint);
        if (earlier != null && today.equals(earlier.getEpoch())) {
            return earlier;
        }
        MemberCredential c = byHub.get(targetKeyFingerprint);
        if (c == null) {
            return null;
        }
        EligibilityProof proof = c.presentEligibility(scheme, auditorKeyFingerprint, today, minMembershipDays,
                challenge);
        if (proof != null) {
            presentedToday.put(targetKeyFingerprint, proof);
        }
        return proof;
    }

    /**
     * Why this device cannot present for a hub, worked out on the device so
     * the target never has to distinguish anything about an anonymous member.
     */
    public synchronized ProberEligibility.Result whyNot(String targetKeyFingerprint, LocalDate today,
                                                        int minMembershipDays) {
        MemberCredential c = byHub.get(targetKeyFingerprint);
        if (scheme != null && c != null && c.isCurrent(today) && c.isAttested()
                && c.getJoinedWeek() > MemberCredential.maxJoinedWeek(today, minMembershipDays)) {
            return ProberEligibility.Result.MEMBERSHIP_TOO_RECENT;
        }
        return ProberEligibility.Result.NO_VALID_CREDENTIAL;
    }

    /** Leaving a hub drops its credential. */
    public synchronized void forget(String hubKeyFingerprint) {
        byHub.remove(hubKeyFingerprint);
        presentedToday.remove(hubKeyFingerprint);
    }
}
