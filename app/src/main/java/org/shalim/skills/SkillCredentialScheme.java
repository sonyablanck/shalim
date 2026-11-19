package org.shalim.skills;

import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import org.shalim.crypto.Signer;

/**
 * The seam where the linkable ring-signature scheme plugs in.
 *
 * <p>Everything around skill credentials is real code from stage 3: who may
 * issue, when, which term, de-duplication, import, discarding the proof after
 * import. The signature itself is not, because the scheme has not been chosen
 * (README open question 18) and it will be an audited library bound over JNI,
 * not hand-written here.
 *
 * <p><strong>There is deliberately no implementation in the main source
 * tree.</strong> The tests use a stand-in that signs with the issuer's key in
 * the open, which is exactly the "hub A's key says this key can use a lathe"
 * form {@link SkillCredential} explains is unacceptable. Shipping that, even as
 * a fallback, would quietly turn every presented skill into a disclosed
 * membership. So without a real scheme, no hub can issue a credential and no
 * hub accepts one: the earning flow fails closed.
 */
public interface SkillCredentialScheme {

    /**
     * Signs a credential for {@code subjectKeyFingerprint} on behalf of one
     * member of {@code ringIssuerKeys}, which must include the key of
     * {@code issuerKey}. The link tag is unique per (issuer, subject, term),
     * so a receiving hub can drop duplicates without learning the issuer.
     */
    SkillCredential issue(String subjectKeyFingerprint, String taxonomyTerm, UserSkill.Proficiency proficiency,
                          LocalDate issuedOn, List<byte[]> ringIssuerKeys, Signer issuerKey);

    /** Verifies against a ring the receiving hub rebuilt from the cards it holds. */
    boolean verify(SkillCredential credential, List<byte[]> ringIssuerKeys, Instant now);
}
