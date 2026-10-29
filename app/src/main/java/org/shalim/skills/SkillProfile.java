package org.shalim.skills;

import java.time.Instant;
import java.util.List;

/**
 * A person's earned skills, held on their own device. The skills counterpart
 * of {@link org.shalim.attestation.AttestationWallet}.
 *
 * <p>The profile travels with the person; hubs do not. When someone joins a
 * hub, or earns something new, they choose which skills to present there. The
 * hub verifies each credential, imports the skill into its member index for
 * matching, and discards the credential — see
 * {@link SkillsLayer#importPresented}.
 */
public class SkillProfile {

    private String ownerKeyFingerprint;

    private List<UserSkill> skills;

    /**
     * Per-hub choices of what to present, keyed by hub id. Kept on the device
     * only. A person may want to be found for bike repair at the makerspace
     * and not at their place of worship.
     */
    private java.util.Map<String, List<String>> presentedByHub;

    public SkillProfile() {
        // TODO: pseudo-code
    }

    /** Stores a newly issued credential, merging with an existing skill for the same term. */
    public UserSkill store(SkillCredential credential) {
        // TODO: pseudo-code
        return null;
    }

    /**
     * Credentials to present to one hub. One per term, never the whole
     * profile unasked — the full set of terms, with their issue dates, says a
     * lot about where someone spends time.
     */
    public List<SkillCredential> presentTo(String hubId, Instant now) {
        // TODO: pseudo-code
        return null;
    }

    public void setPresented(String hubId, List<String> userSkillIds) {
        // TODO: pseudo-code
    }

    public List<UserSkill> getSkills() {
        return skills;
    }

    public String getOwnerKeyFingerprint() {
        return ownerKeyFingerprint;
    }
}
