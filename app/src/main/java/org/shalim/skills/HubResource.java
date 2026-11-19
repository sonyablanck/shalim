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
        this.resourceId = org.shalim.crypto.Bytes.randomId();
        this.skillIds = new java.util.ArrayList<>();
        this.available = true;
        this.kind = Kind.OTHER;
    }

    public HubResource(String hubId, String name, Kind kind) {
        this();
        this.hubId = hubId;
        this.name = name;
        this.kind = kind == null ? Kind.OTHER : kind;
    }

    public HubResource(String hubId, String name, Kind kind, String description, String location) {
        this(hubId, name, kind);
        this.description = description;
        this.location = location;
    }

    /**
     * Asks Matchmaker what competences this resource enables. Called by
     * {@link SkillsLayer#deriveHubSkills}, which merges results across all
     * resources.
     */
    public List<Skill> deriveSkills(org.shalim.ml.MatchmakerEngine matchmaker) {
        return matchmaker == null ? List.of() : matchmaker.deriveHubSkills(List.of(this));
    }

    public void setAvailable(boolean available) {
        this.available = available;
    }

    public void setSkillIds(List<String> ids) {
        this.skillIds = new java.util.ArrayList<>(ids);
    }

    public String getDescription() {
        return description;
    }

    public String getHubId() {
        return hubId;
    }

    public List<String> getSkillIds() {
        return List.copyOf(skillIds);
    }

    /** Restores persisted state. Persistence only. */
    public static HubResource restore(String id, String hubId, String name, Kind kind, String description,
                                      String location, List<String> skillIds, boolean available) {
        HubResource r = new HubResource(hubId, name, kind, description, location);
        r.resourceId = id;
        r.skillIds = new java.util.ArrayList<>(skillIds);
        r.available = available;
        return r;
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
