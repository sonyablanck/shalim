package org.shalim.discovery;

import java.util.List;
import org.shalim.skills.SkillsLayer;

/**
 * Turns a hub's <em>hub skills</em> into at most five {@link SkillTheme}s for
 * its card.
 *
 * <p>Hub skills are derived only from the hub's explicit resource list, so
 * this no longer touches anything about people. The earlier version clustered
 * member skills and dropped any cluster with fewer than five distinct people
 * behind it; that machinery is gone because nothing person-derived reaches
 * here any more. Member skills stay in the private member index, read only by
 * the Matchmaker for members of this hub.
 *
 * <p>Still runs on the hub's own device, on a jittered schedule, and never in
 * response to someone viewing the card.
 */
public class ThemeBuilder {

    private String hubId;

    public ThemeBuilder() {
        // TODO: pseudo-code
    }

    public ThemeBuilder(String hubId) {
        // TODO: pseudo-code
    }

    /** Builds the themes from hub skills. */
    public List<SkillTheme> build(SkillsLayer layer, org.shalim.ml.MatchmakerEngine matchmaker) {
        // PSEUDO-CODE
        //
        // 1. CANDIDATES
        //    candidates = layer.hubSkills WHERE offered AND censor verdict ALLOW
        //    // Never layer.memberIndex. The assertion below makes that a
        //    // failure rather than a convention.
        //
        // 2. RANK
        //    by number of available resources behind each skill, then by name
        //
        // 3. TRIM to HubCard.MAX_THEMES
        //
        // 4. LABEL
        //    theme.label = skill.label   // already screened at HUB_PROFILE
        //
        // 5. ASSERT every theme's source is a hub skill. If not, return nothing
        //    and log: a person-derived theme on a public card is a bug in the
        //    pipeline, not a theme to filter out.
        return null;
    }

    public boolean isStale(java.time.Instant lastBuiltAt, java.time.Instant now) {
        // TODO: pseudo-code
        return false;
    }

    public String getHubId() {
        return hubId;
    }
}
