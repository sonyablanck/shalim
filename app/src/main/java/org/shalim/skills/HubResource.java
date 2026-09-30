package org.shalim.skills;

import java.util.List;

/**
 * A non-human asset a hub holds: books, tools, machines, rooms, seed stock.
 *
 * <p>Every hub starts with an explicit list of these, and they are the only
 * source of the hub's {@link Skill}s. They are also how people earn skills:
 * using a resource, verified by an admin, earns the user skill it affords
 * (see {@link ResourceInteraction}).
 */
public class HubResource {

    private String resourceId;
    private String hubId;
    private String name;
    private String description;
    private Kind kind;

    /** Where in the hub it physically is. Matters when the network is down. */
    private String location;

    /** Skills this resource affords, derived from its description. */
    private List<String> skillIds;

    private boolean available;

    public enum Kind {
        BOOK,
        TOOL,
        MACHINE,
        SPACE,
        MATERIAL,
        DOCUMENT,
        OTHER
    }

    public HubResource() {
        // TODO: pseudo-code
    }

    public HubResource(String hubId, String name, Kind kind) {
        // TODO: pseudo-code
    }

    /**
     * Asks Matchmaker what competences this resource enables. Called by
     * {@link SkillsLayer#deriveHubSkills}, which merges results across all
     * resources.
     */
    public List<Skill> deriveSkills(org.shalim.ml.MatchmakerEngine matchmaker) {
        // TODO: pseudo-code
        return null;
    }

    public void setAvailable(boolean available) {
        // TODO: pseudo-code
    }

    // --- accessors --------------------------------------------------------

    public String getResourceId() {
        return resourceId;
    }

    public String getName() {
        return name;
    }

    public Kind getKind() {
        return kind;
    }

    public String getLocation() {
        return location;
    }

    public boolean isAvailable() {
        return available;
    }
}
