package org.shalim.skills;

import java.time.Instant;
import java.util.List;

/**
 * A <em>hub skill</em>: something a hub makes it possible to learn or do,
 * derived by the Matchmaker from the hub's explicit list of
 * {@link HubResource}s. "Hand-tool woodworking" because there is a workbench
 * and chisels; "seed saving" because there is a seed library.
 *
 * <p>Hub skills are what hub search shows. They describe the hub's resources
 * and nothing else, so they can be shown to strangers without saying anything
 * about any person — the reason the old five-person anonymity floor no longer
 * applies to discovery.
 *
 * <p>People's skills are a different class, {@link UserSkill}, held by the
 * person rather than the hub. A hub skill is also the unit a person earns:
 * using the workbench, verified by an admin, earns the user skill that this
 * hub skill names.
 */
public class Skill {

    private String skillId;
    private String hubId;

    /** Where this hub skill came from. There is no USER origin any more. */
    private Origin origin;

    /** Resources this skill was derived from. At least one. */
    private List<String> resourceIds;

    /** Matchmaker's phrasing for this hub. Screened at HUB_PROFILE. */
    private String label;

    /**
     * Term in the shared, release-pinned skill taxonomy. Earned credentials
     * carry this, never {@link #label}: a hub-specific label on a portable
     * credential would identify the hub that issued it.
     */
    private String taxonomyTerm;

    /** Used for ranking. Regenerated on model change. */
    private String normalisedText;

    /** False when every resource behind it is unavailable. */
    private boolean offered;

    private Instant derivedAt;

    /** Matchmaker pin that derived it, so a model change can trigger re-derivation. */
    private String derivedByPinHash;

    private String censorVerdictId;

    public enum Origin {
        /** Derived from one or more hub resources. The normal case. */
        RESOURCE,
        /** Inferred from a combination of resources. Always shown as inferred. */
        INFERRED
    }

    public Skill() {
        // TODO: pseudo-code
    }

    public Skill(String hubId, Origin origin, List<String> resourceIds, String label) {
        // TODO: pseudo-code
    }

    /** Whether any resource behind this skill is currently available. */
    public boolean isBackedBy(List<HubResource> resources) {
        // TODO: pseudo-code
        return false;
    }

    public void setOffered(boolean offered) {
        // TODO: pseudo-code
    }

    // --- accessors --------------------------------------------------------

    public String getSkillId() {
        return skillId;
    }

    public String getHubId() {
        return hubId;
    }

    public Origin getOrigin() {
        return origin;
    }

    public List<String> getResourceIds() {
        return resourceIds;
    }

    public String getLabel() {
        return label;
    }

    public String getTaxonomyTerm() {
        return taxonomyTerm;
    }

    public String getNormalisedText() {
        return normalisedText;
    }

    public boolean isOffered() {
        return offered;
    }

    public Instant getDerivedAt() {
        return derivedAt;
    }

    public String getCensorVerdictId() {
        return censorVerdictId;
    }
}
