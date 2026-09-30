package org.shalim.trust;

import java.time.Instant;
import java.util.List;

/**
 * What a hub card publishes about one of its {@link AuthBond}s: proof that
 * <em>some</em> listed hub is currently bonded with this one, without naming
 * which.
 *
 * <h2>Why not just publish the bonds</h2>
 *
 * <p>Hub search has to count bonds, so the count has to be on the card, and a
 * count the hub asserts about itself is worthless — anyone can type "5". The
 * obvious verifiable form is the co-signed bonds themselves. But a bond
 * between A and B exists only because an admin of A is a member of B and an
 * admin of B is a member of A. Publishing bonds would publish a map of which
 * communities' organisers sit in which other communities, which the rest of
 * this design treats as the single most dangerous artefact it could build.
 *
 * <h2>What this does instead</h2>
 *
 * <p>The bonded peer signs with a <em>linkable ring signature</em> over the
 * issuer keys of every currently listed hub in the region (the "ring"). A
 * verifier can check that the signer is one of the ring, cannot tell which,
 * and can tell whether two proofs on the same card came from the same signer
 * — via {@link #linkTag}, which is unique per (signer, subject, epoch). So a
 * card can prove "three distinct listed hubs are bonded with me" without
 * naming them, and cannot inflate the count by having one peer sign three
 * times.
 *
 * <h2>What it still leaks</h2>
 * <ul>
 *   <li>The count itself. A hub with five bonds is visibly better connected
 *       than one with one, which is a signal about its organisers.</li>
 *   <li>Anonymity is only as large as the ring. In a region with four listed
 *       hubs, "one of these four" is not much of a secret.</li>
 *   <li>Nothing here stops one person running three hubs and bonding them
 *       together. The ring proves signers are distinct hubs, not distinct
 *       people.</li>
 * </ul>
 */
public class BondProof {

    /** Subject hub's issuer key fingerprint — the hub whose card this is on. */
    private String subjectKeyFingerprint;

    /** Hash of the ring the signature is over; verifiers rebuild it from held cards. */
    private String ringHash;

    /** Unique per (signer, subject, epoch). Equal tags on one card = one signer. */
    private String linkTag;

    /** Day-granular epoch the proof is valid for. */
    private Instant epochStart;
    private Instant expiresAt;

    private byte[] ringSignature;

    public BondProof() {
        // TODO: pseudo-code
    }

    /**
     * Verifies on the searcher's device, against cards it already holds. Makes
     * no network call.
     */
    public boolean verify(List<byte[]> ringIssuerKeys, Instant now) {
        // PSEUDO-CODE
        // IF now > expiresAt -> RETURN false
        // IF hash(ringIssuerKeys) != ringHash -> RETURN false
        //    // The device holds a different set of cards from the signer. Common
        //    // at region edges and after a partition; the proof is simply not
        //    // counted, and the card may drop below threshold on this device.
        // RETURN lsagVerify(ringSignature, message = (subject, epoch), ringIssuerKeys)
        return false;
    }

    // --- accessors --------------------------------------------------------

    public String getSubjectKeyFingerprint() {
        return subjectKeyFingerprint;
    }

    public String getRingHash() {
        return ringHash;
    }

    public String getLinkTag() {
        return linkTag;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }
}
