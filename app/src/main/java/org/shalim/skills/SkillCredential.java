package org.shalim.skills;

import java.time.Instant;
import java.util.List;

/**
 * Signed proof that a person earned a skill at <em>some authenticated hub</em>,
 * without saying which.
 *
 * <h2>Why the issuer is hidden</h2>
 *
 * <p>User skills are portable: a hub matches its members on skills they earned
 * anywhere. The simple form — "hub A's key says this key can use a lathe" —
 * would tell every hub a person presents it to that they are a member of hub
 * A. Present five credentials and the receiving hub knows five of your
 * memberships: the cross-hub membership graph, assembled one person at a time.
 *
 * <p>So the issuing hub signs with a ring signature over the issuer keys of
 * the hubs currently listed in search in its region (the same ring as
 * {@link org.shalim.trust.BondProof}). A receiving hub can check that an
 * authenticated, listed hub issued it, and cannot tell which. This also means
 * an unauthenticated hub cannot issue portable credentials at all — its key is
 * not in any ring — which stops a newly-minted hub farming skills for anyone.
 *
 * <h2>What still links a credential to a hub</h2>
 * <ul>
 *   <li>{@link #taxonomyTerm} is a shared, coarse term ("metalwork"), not the
 *       hub's own label ("the Tuesday lathe club"). A rare term in a small
 *       region can still point at the only hub with that resource.</li>
 *   <li>{@link #issuedOn} is day-granular for the same reason.</li>
 *   <li>A ring is only as anonymous as it is large.</li>
 * </ul>
 */
public class SkillCredential {

    private String credentialId;

    /** Holder's key fingerprint. Re-bound on guest upgrade. */
    private String subjectKeyFingerprint;

    private String taxonomyTerm;

    private UserSkill.Proficiency proficiency;

    /** Day-granular. */
    private java.time.LocalDate issuedOn;

    /** Hash of the ring of listed issuer keys the signature is over. */
    private String ringHash;

    private byte[] ringSignature;

    /**
     * Unique per (issuer, subject, term). Lets a receiving hub drop duplicates
     * of the same credential without learning the issuer.
     */
    private String linkTag;

    /** Grace window for rings that have since rotated. */
    public static final java.time.Duration RING_GRACE = java.time.Duration.ofDays(30);

    public SkillCredential() {
    }

    /** Built by a {@link SkillCredentialScheme}, or restored from the holder's device. */
    public SkillCredential(String credentialId, String subjectKeyFingerprint, String taxonomyTerm,
                           UserSkill.Proficiency proficiency, java.time.LocalDate issuedOn, String ringHash,
                           byte[] ringSignature, String linkTag) {
        this.credentialId = credentialId;
        this.subjectKeyFingerprint = subjectKeyFingerprint;
        this.taxonomyTerm = taxonomyTerm;
        this.proficiency = proficiency;
        this.issuedOn = issuedOn;
        this.ringHash = ringHash;
        this.ringSignature = ringSignature == null ? null : ringSignature.clone();
        this.linkTag = linkTag;
    }

    /** What the ring signature signs. The scheme decides how. */
    public byte[] signedPayload() {
        return org.shalim.crypto.Canonical.of("shalim.skillcredential.v1").hex(subjectKeyFingerprint)
                .string(taxonomyTerm).enumName(proficiency)
                .u64(issuedOn == null ? Long.MIN_VALUE : issuedOn.toEpochDay()).hex(ringHash).encode();
    }

    /** Hash of a ring: SHA-256 over the sorted raw keys, so order never matters. */
    public static String ringHashOf(List<byte[]> ringIssuerKeys) {
        List<String> hexKeys = new java.util.ArrayList<>();
        for (byte[] k : ringIssuerKeys) {
            hexKeys.add(org.shalim.crypto.Bytes.hex(k));
        }
        return org.shalim.crypto.Canonical.of("shalim.ring.v1").strings(hexKeys).digestHex();
    }

    /**
     * Verifies against a ring the receiving hub rebuilds from the cards it
     * holds. Rings rotate as hubs join and leave search, so a credential is
     * checked against the current ring and against recent rings the caller
     * still holds within {@link #RING_GRACE}. With no scheme bound, nothing
     * verifies.
     */
    public boolean verify(List<List<byte[]>> currentAndRecentRings, SkillCredentialScheme scheme, Instant now) {
        if (scheme == null || ringSignature == null || ringHash == null) {
            return false;
        }
        for (List<byte[]> ring : currentAndRecentRings) {
            if (org.shalim.crypto.Bytes.equalHex(ringHash, ringHashOf(ring)) && scheme.verify(this, ring, now)) {
                return true;
            }
        }
        return false;
    }

    public String getRingHash() {
        return ringHash;
    }

    public byte[] getRingSignature() {
        return ringSignature == null ? null : ringSignature.clone();
    }

    // --- accessors --------------------------------------------------------

    public String getCredentialId() {
        return credentialId;
    }

    public String getSubjectKeyFingerprint() {
        return subjectKeyFingerprint;
    }

    public String getTaxonomyTerm() {
        return taxonomyTerm;
    }

    public UserSkill.Proficiency getProficiency() {
        return proficiency;
    }

    public java.time.LocalDate getIssuedOn() {
        return issuedOn;
    }

    public String getLinkTag() {
        return linkTag;
    }
}
