package org.shalim.trust;

import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import org.shalim.hub.CensorDecisionLog;

/**
 * What an authenticating hub sees of a peer it checks: the hub-to-hub half of
 * link setup, replay and statements. {@link AuditResponder} is the real
 * target side; in the running system these calls travel over ordinary sync
 * between hub instances, carried on an authenticated session. Nothing here is
 * routed through the prober's membership, so nothing here ties a request to a
 * member.
 */
public interface LinkPeer {

    String keyFingerprint();

    byte[] publicKey();

    /** A fresh challenge for a credential presentation. */
    byte[] newChallenge();

    /**
     * PSI-CA, first round: takes the authenticating hub's blinded admins and
     * returns the target's own admins, blinded with a fresh exponent.
     */
    List<byte[]> overlapRound1(String auditorKeyFingerprint, List<byte[]> auditorBlinded);

    /** PSI-CA, second round: the target's admins, double-blinded by the auditor. Only the target learns the count. */
    void overlapRound2(String auditorKeyFingerprint, List<byte[]> targetDoubleBlinded);

    /** Asks to set up a link. The target's admins then accept or decline the <em>hub</em>, never the person. */
    ProberEligibility.Result requestLink(LinkRequest request, Instant now);

    /** The daily re-presentation that keeps a link eligible. */
    ProberEligibility.Result presentDaily(String auditorKeyFingerprint, EligibilityProof proof, Instant now);

    /** The signed head for a closed day, as sync would carry it. Null if not closed or not held. */
    CensorDecisionLog.SignedTreeHead head(LocalDate day, Instant now);

    /**
     * Openings for one day's sample. The target checks the nonce against the
     * committed chain and derives the indices itself; the auditor never names
     * an index. Null means no answer (offline, not linked), which is not a
     * refusal.
     */
    List<CensorDecisionLog.Opening> open(String auditorKeyFingerprint, LocalDate day, byte[] dayNonce, int size,
                                         Instant now);

    /** Delivers the auditor's signed statement about the link. */
    boolean deliverStatement(LinkStatement statement, Instant now);

    /** What a link request carries. No user id: the prober is a proof and two pseudonyms. */
    record LinkRequest(String auditorKeyFingerprint, byte[] auditorPublicKey, byte[] auditorEncryptionKey,
                       EligibilityProof proof, byte[] nonceAnchor, LocalDate chainStart) {
    }
}
