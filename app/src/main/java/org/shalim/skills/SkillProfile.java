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
        this.skills = new java.util.ArrayList<>();
        this.presentedByHub = new java.util.HashMap<>();
    }

    public SkillProfile(String ownerKeyFingerprint) {
        this();
        this.ownerKeyFingerprint = ownerKeyFingerprint;
    }

    /** Stores a newly issued credential, merging with an existing skill for the same term. */
    public synchronized UserSkill store(SkillCredential credential) {
        if (credential == null || (ownerKeyFingerprint != null
                && !ownerKeyFingerprint.equals(credential.getSubjectKeyFingerprint()))) {
            return null;
        }
        for (UserSkill s : skills) {
            if (java.util.Objects.equals(s.getTaxonomyTerm(), credential.getTaxonomyTerm())) {
                s.reconfirm(credential);
                return s;
            }
        }
        UserSkill s = new UserSkill(credential);
        skills.add(s);
        return s;
    }

    /**
     * Credentials to present to one hub: only those the person chose for that
     * hub, and only those they still offer. Nothing is presented by default:
     * the full set of terms, with their issue dates, says a lot about where
     * someone spends time.
     */
    public synchronized List<SkillCredential> presentTo(String hubId, Instant now) {
        List<String> chosen = presentedByHub.getOrDefault(hubId, List.of());
        List<SkillCredential> out = new java.util.ArrayList<>();
        for (UserSkill s : skills) {
            if (chosen.contains(s.getUserSkillId()) && s.isOffered() && s.getCredential() != null) {
                out.add(s.getCredential());
            }
        }
        return out;
    }

    public synchronized void setPresented(String hubId, List<String> userSkillIds) {
        if (userSkillIds == null || userSkillIds.isEmpty()) {
            presentedByHub.remove(hubId);
        } else {
            presentedByHub.put(hubId, List.copyOf(userSkillIds));
        }
    }

    public List<UserSkill> getSkills() {
        return skills;
    }

    public String getOwnerKeyFingerprint() {
        return ownerKeyFingerprint;
    }
}
