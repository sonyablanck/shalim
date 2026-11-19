package org.shalim.attestation;

import java.time.Instant;
import java.util.List;

/**
 * The proofs a user currently holds, stored on their own device.
 *
 * <p>User-held so no hub keeps a roster of where its members also belong. The
 * wallet knows which hubs issued its proofs, but nothing outside the device
 * ever sees more than one proof at a time, and a proof names only its issuer's
 * key fingerprint.
 */
public class AttestationWallet {

    private String ownerKeyFingerprint;
    private List<Attestation> attestations;

    public AttestationWallet() {
        this.attestations = new java.util.ArrayList<>();
    }

    public AttestationWallet(String ownerKeyFingerprint) {
        this();
        this.ownerKeyFingerprint = ownerKeyFingerprint;
    }

    /**
     * Stores a freshly issued proof, replacing any older one of the same claim
     * from the same issuer. Proofs about someone else are refused: a wallet
     * holding another person's proofs could present them.
     */
    public synchronized void store(Attestation attestation) {
        if (attestation == null || (ownerKeyFingerprint != null
                && !ownerKeyFingerprint.equals(attestation.getSubjectKeyFingerprint()))) {
            return;
        }
        attestations.removeIf(a -> a.getClaim() == attestation.getClaim()
                && java.util.Objects.equals(a.getIssuerKeyFingerprint(), attestation.getIssuerKeyFingerprint())
                && (attestation.getClaim() != Attestation.Claim.ACTIVE_MODERATION_OUTCOME
                    || java.util.Objects.equals(a.getOutcomeId(), attestation.getOutcomeId())));
        attestations.add(attestation);
    }

    /**
     * Best currently-valid proof of the given claim that a verifier would
     * accept, or empty if none. Emptiness is what caps the user. Presents ONE
     * proof, never the set: handing over the whole wallet would reveal every
     * hub the user belongs to, which is the cross-hub graph this design exists
     * to avoid.
     */
    public synchronized java.util.Optional<Attestation> present(Attestation.Claim claim,
                                                                List<String> acceptedIssuers,
                                                                Instant now) {
        Attestation best = null;
        for (Attestation a : attestations) {
            if (a.getClaim() == claim && a.isValid(now)
                    && acceptedIssuers != null && acceptedIssuers.contains(a.getIssuerKeyFingerprint())
                    && (best == null || a.getExpiresAt().isAfter(best.getExpiresAt()))) {
                best = a;
            }
        }
        return java.util.Optional.ofNullable(best);
    }

    /** Drops expired proofs. Expiry is how a stale good-standing claim clears itself. */
    public synchronized int prune(Instant now) {
        int before = attestations.size();
        attestations.removeIf(a -> a.getExpiresAt() == null || !now.isBefore(a.getExpiresAt()));
        return before - attestations.size();
    }

    /** Proofs close to expiry, so the app can refresh them while connectivity lasts. */
    public synchronized List<Attestation> needingRefresh(Instant now) {
        List<Attestation> out = new java.util.ArrayList<>();
        for (Attestation a : attestations) {
            if (a.isValid(now) && a.needsRefresh(now)) {
                out.add(a);
            }
        }
        return out;
    }

    /** Removes everything from one issuer. Called when the user leaves that hub. */
    public synchronized int forgetIssuer(String issuerKeyFingerprint) {
        int before = attestations.size();
        attestations.removeIf(a -> java.util.Objects.equals(a.getIssuerKeyFingerprint(), issuerKeyFingerprint));
        return before - attestations.size();
    }

    public synchronized int size() {
        return attestations.size();
    }

    /** Everything held, for persistence on the owner's own device. */
    public synchronized List<Attestation> all() {
        return List.copyOf(attestations);
    }

    public String getOwnerKeyFingerprint() {
        return ownerKeyFingerprint;
    }
}
