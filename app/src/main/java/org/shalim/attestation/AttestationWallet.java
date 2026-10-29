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
        // TODO: pseudo-code
    }

    /** Stores a freshly issued proof, replacing any older one from the same issuer. */
    public void store(Attestation attestation) {
        // TODO: pseudo-code
    }

    /**
     * Best currently-valid proof of the given claim that a verifier would
     * accept, or empty if none. Emptiness is what caps the user.
     */
    public java.util.Optional<Attestation> present(Attestation.Claim claim,
                                                   List<String> acceptedIssuers,
                                                   Instant now) {
        // PSEUDO-CODE
        //
        // candidates = attestations WHERE claim matches
        //                             AND isValid(now)
        //                             AND issuerKeyFingerprint IN acceptedIssuers
        // RETURN the one expiring latest, or empty
        //    // Presents ONE proof, never the set. Handing over the whole wallet
        //    // would reveal every hub the user belongs to — precisely the
        //    // cross-hub graph this design exists to avoid.
        return java.util.Optional.empty();
    }

    /** Drops expired proofs. Expiry is how a stale good-standing claim clears itself. */
    public int prune(Instant now) {
        // TODO: pseudo-code
        return 0;
    }

    /** Proofs close to expiry, so the app can refresh them while connectivity lasts. */
    public List<Attestation> needingRefresh(Instant now) {
        // TODO: pseudo-code
        return null;
    }

    /** Removes everything from one issuer. Called when the user leaves that hub. */
    public int forgetIssuer(String issuerKeyFingerprint) {
        // TODO: pseudo-code
        return 0;
    }

    public String getOwnerKeyFingerprint() {
        return ownerKeyFingerprint;
    }
}
