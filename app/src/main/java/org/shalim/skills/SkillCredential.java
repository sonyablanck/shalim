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

    public SkillCredential() {
        // TODO: pseudo-code
    }

    /**
     * Verifies against a ring the receiving hub rebuilds from the cards it
     * holds. Rings rotate as hubs join and leave search, so verification also
     * accepts any ring the hub has held within the credential's grace window.
     */
    public boolean verify(List<byte[]> ringIssuerKeys, Instant now) {
        // PSEUDO-CODE
        // IF hash(ringIssuerKeys) != ringHash AND ring not in recent-ring cache
        //    RETURN false
        // RETURN lsagVerify(ringSignature, (subject, term, proficiency, issuedOn), ring)
        return false;
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
