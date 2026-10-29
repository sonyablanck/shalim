package org.shalim.discovery;

/**
 * One line of "what this hub is good at", shown on its card to strangers.
 *
 * <p>A theme is a {@link org.shalim.skills.Skill hub skill} — derived from the
 * hub's resources, never from its people. That is the whole safety argument:
 * a lathe, a seed library and a shelf of legal textbooks cannot be inferred
 * back to a person, so a theme can be shown to anyone without an anonymity
 * floor. Earlier versions built themes from member skills and needed a
 * five-person floor to stop a theme resolving to one person in a small hub;
 * since hub skills became resource-only, that risk is gone at source.
 */
public class SkillTheme {

    /** The hub skill's label, e.g. "bike repair", "seed saving". Screened at HUB_PROFILE. */
    private String label;

    /** Shared taxonomy term, so searches match across hubs' differing labels. */
    private String taxonomyTerm;

    /** Rank on the card, 1 to 5. */
    private int rank;

    /** Hub skill this theme shows. Never a user skill. */
    private String hubSkillId;

    private String censorVerdictId;

    public SkillTheme() {
        // TODO: pseudo-code
    }

    public SkillTheme(String label, int rank) {
        // TODO: pseudo-code
    }

    /** Whether this theme may be shown to someone who is not a member. */
    public boolean isPublishable() {
        // PSEUDO-CODE
        // RETURN censorVerdictId != null AND hubSkillId != null
        return false;
    }

    public String getLabel() {
        return label;
    }

    public String getTaxonomyTerm() {
        return taxonomyTerm;
    }

    public int getRank() {
        return rank;
    }

    public String getHubSkillId() {
        return hubSkillId;
    }

    public String getCensorVerdictId() {
        return censorVerdictId;
    }
}
