package org.shalim.hub;

import java.time.Instant;
import java.util.Objects;
import org.shalim.skills.SkillsLayer;

/**
 * Plain hub state: identity, policy, premises, network, membership roster,
 * resources and authentication standing. Runtime services live in HubRuntime
 * instead of here.
 *
 * <p>A hub is created with an explicit list of {@link org.shalim.skills.HubResource}s.
 * Its hub skills — what search shows strangers — are derived from those
 * resources by the Matchmaker, and nothing else feeds them.
 */
public class Hub {

    private String hubId;
    private String name;
    private String description;
    private Instant createdAt;
    private long revision;

    private HubPolicy policy;
    private HubLocation location;
    private HubNetwork network;
    private HubLog log;
    private SkillsLayer skillsLayer;
    private Roster roster;

    /**
     * Observed authentication standing. Starts UNAUTHENTICATED, so a new hub's
     * non-admin members are guests until an admin sets up authentication.
     */
    private HubStanding standing;

    /**
     * Committed record of every censor decision, for replay by authenticating
     * hubs. State, not a service: see {@link CensorDecisionLog}.
     */
    private CensorDecisionLog censorLog;

    public Hub() {
        this.createdAt = Instant.now();
        this.log = new HubLog();
        this.roster = new Roster();
        this.skillsLayer = new SkillsLayer();
    }

    public Hub(String hubId, String name, HubPolicy policy) {
        this();
        this.hubId = hubId;
        this.name = name;
        this.policy = policy;
    }

    public Hub(String hubId, String name, HubPolicy policy,
               HubLocation location, HubNetwork network, String foundingAdminUserId,
               java.util.List<org.shalim.skills.HubResource> initialResources) {
        this(hubId, name, policy, location, network, foundingAdminUserId);
        // PSEUDO-CODE
        // IF NetworkClaimService.mayCreateHubHere(observed BSSIDs,
        //       claims pinned on this device, now) != ALLOWED
        //    -> refuse creation; offer the answering hub's card to join instead
        //    // Checked before this hub's keys are made. No hub may be created on
        //    // another hub's network.
        // network.claim = new NetworkClaim(hub key, salted BSSID hashes, now)
        // FOR EACH resource IN initialResources
        //    skillsLayer.addResource(resource, censor)   // screened at RESOURCE_DESCRIPTION
        // skillsLayer.deriveHubSkills(matchmaker)        // by the runtime at first start
        // standing = UNAUTHENTICATED
        // log HUB_CREATED, RESOURCE_ADDED per resource
    }

    public Hub(String hubId, String name, HubPolicy policy,
               HubLocation location, HubNetwork network, String foundingAdminUserId) {
        this(hubId, name, policy);
        this.location = location;
        this.network = network;
        this.log = new HubLog(hubId);
        this.roster = new Roster();
        if (foundingAdminUserId != null && !foundingAdminUserId.isBlank()) {
            this.roster.add(new org.shalim.identity.Membership(
                foundingAdminUserId, hubId, org.shalim.identity.Role.ADMIN));
        }
    }

    public boolean isViable() {
        return location != null
            && location.isComplete()
            && network != null
            && network.getClaim() != null
            && !network.isDisputed()
            // One hub per network. A disputed hub is not listed until it
            // migrates or the other claimant goes away.
            && roster != null
            && roster.adminCount() >= 1
            && log != null
            && skillsLayer != null
            && skillsLayer.hasResources();
            // A hub with no resources has no hub skills, and nothing for
            // anyone — guests included — to earn skills from.
    }

    public void mergeFrom(Hub peerCopy) {
        if (peerCopy == null) {
            return;
        }
        if (this.hubId == null) {
            this.hubId = peerCopy.hubId;
        }
        if (this.name == null) {
            this.name = peerCopy.name;
        }
        if (this.description == null) {
            this.description = peerCopy.description;
        }
        if (this.createdAt == null) {
            this.createdAt = peerCopy.createdAt;
        }
        if (this.policy == null) {
            this.policy = peerCopy.policy;
        }
        if (this.location == null) {
            this.location = peerCopy.location;
        }
        if (this.network == null) {
            this.network = peerCopy.network;
        }
        if (this.log == null) {
            this.log = peerCopy.log;
        }
        if (this.skillsLayer == null) {
            this.skillsLayer = peerCopy.skillsLayer;
        }
        if (this.roster == null) {
            this.roster = peerCopy.roster;
        }
        // Standing is never merged from a peer copy. It is recomputed locally
        // from this hub's own WebOfTrust, so a peer cannot hand a hub a
        // standing it has not earned.
        if (peerCopy.revision > this.revision) {
            this.revision = peerCopy.revision;
        }
    }

    public void bumpRevision() {
        this.revision += 1;
    }

    public String getHubId() {
        return hubId;
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public long getRevision() {
        return revision;
    }

    public HubPolicy getPolicy() {
        return policy;
    }

    public HubLocation getLocation() {
        return location;
    }

    public HubNetwork getNetwork() {
        return network;
    }

    public HubLog getLog() {
        return log;
    }

    public SkillsLayer getSkillsLayer() {
        return skillsLayer;
    }

    public Roster getRoster() {
        return roster;
    }

    public HubStanding getStanding() {
        return standing;
    }

    public void setStanding(HubStanding standing) {
        this.standing = standing;
    }

    public CensorDecisionLog getCensorLog() {
        return censorLog;
    }

    public void setCensorLog(CensorDecisionLog censorLog) {
        this.censorLog = censorLog;
    }

    public void setHubId(String hubId) {
        this.hubId = hubId;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public void setPolicy(HubPolicy policy) {
        this.policy = policy;
    }

    public void setLocation(HubLocation location) {
        this.location = location;
    }

    public void setNetwork(HubNetwork network) {
        this.network = network;
    }

    public void setLog(HubLog log) {
        this.log = log;
    }

    public void setSkillsLayer(SkillsLayer skillsLayer) {
        this.skillsLayer = skillsLayer;
    }

    public void setRoster(Roster roster) {
        this.roster = roster;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        Hub hub = (Hub) o;
        return Objects.equals(hubId, hub.hubId)
            && Objects.equals(name, hub.name)
            && Objects.equals(description, hub.description)
            && Objects.equals(createdAt, hub.createdAt);
    }

    @Override
    public int hashCode() {
        return Objects.hash(hubId, name, description, createdAt);
    }
}
