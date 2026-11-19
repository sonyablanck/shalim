package org.shalim.testing;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.List;
import java.util.Map;
import org.shalim.crypto.Bytes;
import org.shalim.crypto.Canonical;
import org.shalim.crypto.Ed25519;
import org.shalim.crypto.Fingerprints;
import org.shalim.crypto.Signer;
import org.shalim.crypto.SoftwareSigner;
import org.shalim.hub.Hub;
import org.shalim.hub.HubAdministration;
import org.shalim.hub.HubLocation;
import org.shalim.hub.HubNetwork;
import org.shalim.hub.HubPolicy;
import org.shalim.hub.HubRuntime;
import org.shalim.hub.HubStanding;
import org.shalim.hub.NetworkClaim;
import org.shalim.hub.NetworkClaimService;
import org.shalim.ml.CensorEngine;
import org.shalim.ml.stub.FixedCensor;
import org.shalim.ml.stub.KeywordMatchmaker;
import org.shalim.skills.HubResource;
import org.shalim.skills.SkillCredential;
import org.shalim.skills.SkillCredentialScheme;
import org.shalim.skills.UserSkill;

/** A created hub with stub models, keys, a movable clock and a test-only credential scheme. */
public final class HubFixture {

    public static final Instant T0 = Instant.parse("2026-11-18T10:00:00Z");

    /** A clock tests can move forward. */
    public static final class MovableClock extends Clock {
        private Instant now;

        public MovableClock(Instant start) {
            this.now = start;
        }

        public void advance(Duration d) {
            now = now.plus(d);
        }

        @Override
        public ZoneId getZone() {
            return ZoneId.of("UTC");
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    /**
     * Signs credentials with the issuer's key in the open. FOR TESTS ONLY: it
     * reveals the issuing hub, which is exactly what the real scheme must not.
     */
    public static final class OpenSignatureScheme implements SkillCredentialScheme {
        @Override
        public SkillCredential issue(String subject, String term, UserSkill.Proficiency proficiency, LocalDate day,
                                     List<byte[]> ring, Signer issuerKey) {
            String ringHash = SkillCredential.ringHashOf(ring);
            SkillCredential unsigned = new SkillCredential(Bytes.randomId(), subject, term, proficiency, day, ringHash,
                    null, null);
            byte[] sig = Bytes.concat(issuerKey.publicKey(), issuerKey.sign(unsigned.signedPayload()));
            String tag = Canonical.of("test.linktag").bytes(issuerKey.publicKey()).hex(subject).string(term).digestHex();
            return new SkillCredential(unsigned.getCredentialId(), subject, term, proficiency, day, ringHash, sig, tag);
        }

        @Override
        public boolean verify(SkillCredential c, List<byte[]> ring, java.time.Instant now) {
            byte[] sig = c.getRingSignature();
            if (sig == null || sig.length != 96) {
                return false;
            }
            byte[] pub = java.util.Arrays.copyOfRange(sig, 0, 32);
            boolean inRing = ring.stream().anyMatch(k -> Bytes.equal(k, pub));
            return inRing && Ed25519.verify(pub, c.signedPayload(), java.util.Arrays.copyOfRange(sig, 32, 96));
        }
    }

    public final MovableClock clock;
    public final SoftwareSigner hubKey = SoftwareSigner.generate();
    public final byte[] atRestKey = Bytes.random(32);
    public final byte[] salt = Bytes.random(32);
    public final SoftwareSigner admin = SoftwareSigner.generate();
    public final FixedCensor censor;
    public final KeywordMatchmaker matchmaker;
    public final HubRuntime runtime;
    public final Hub hub;
    public final HubAdministration admin() {
        return new HubAdministration(hub, runtime);
    }

    public HubFixture() {
        this(HubPolicy.Posture.COMMUNITY);
    }

    public HubFixture(HubPolicy.Posture posture) {
        this(posture, new MovableClock(T0), null, null);
    }

    /**
     * A hub on a shared clock, optionally with its own censor and a name, so
     * several hubs can live in one test.
     */
    public HubFixture(HubPolicy.Posture posture, MovableClock sharedClock, CensorEngine censorOverride, String name) {
        this.clock = sharedClock;
        censor = standardCensor(clock);
        matchmaker = new KeywordMatchmaker(censor, Map.of("lathe", "metalwork", "seed", "gardening",
                "compost", "gardening", "sewing", "textiles"));
        try {
            censor.load();
            matchmaker.load();
        } catch (Exception e) {
            throw new AssertionError(e);
        }
        CensorEngine screening = censorOverride == null ? censor : censorOverride;
        try {
            screening.load();
        } catch (Exception e) {
            throw new AssertionError(e);
        }
        HubRuntime base = new HubRuntime(null, screening, matchmaker, null, null, null)
                .withKeys(hubKey, atRestKey).withClock(clock)
                .withCredentials(new OpenSignatureScheme(), () -> List.of(List.of(hubKey.publicKey())));
        HubPolicy policy = HubPolicy.defaultsFor(posture);
        policy.setRequiredCensorPinHash(screening.pin().getArtefactHash());
        HubLocation location = new HubLocation(null, "Hastings Library, 2nd floor", "13 Brassey Road, Hastings",
                HubLocation.Precision.APPROXIMATE);
        location.setLocality("Hastings");
        location.setOpeningHours("Daily 08:00-22:00", "Europe/London");
        location.setSupervised(true);
        location.setPubliclyAccessible(true);
        location.setMeetingSpaces(List.of("study room 3"));
        location.setApproxPosition(50.8558, 0.5806);
        NetworkClaim claim = NetworkClaimService.createClaim(List.of("00:11:22:33:44:01"), salt, hubKey, T0);
        HubNetwork network = new HubNetwork(null, "Library", claim.getSaltedBssidHashes(), true, true, true);
        network.setClaim(claim);
        List<HubResource> resources = List.of(
                new HubResource(null, "Lathe", HubResource.Kind.MACHINE, "A small metal lathe", "workshop"),
                new HubResource(null, "Seed library", HubResource.Kind.BOOK, "Seed packets and compost guides", "shelf 4"),
                new HubResource(null, "blockme kit", HubResource.Kind.OTHER, "refused", "nowhere"));
        HubAdministration.Created created = HubAdministration.create(new HubAdministration.Creation(name == null ? "Hastings Commons" : name,
                "Tools and seeds", policy, location, network, admin.fingerprint(), resources), base);
        if (!created.ok()) {
            throw new AssertionError("fixture hub not created: " + created.problems());
        }
        hub = created.hub();
        runtime = base.forHub(hub);
    }

    /** The stub censor every fixture hub screens with, unless told otherwise. */
    public static FixedCensor standardCensor(Clock clock) {
        return new FixedCensor(Map.of(
                "blockme", new FixedCensor.Rule(CensorEngine.Decision.BLOCK, CensorEngine.Category.WEAPONS_SUPPLY, 0.97f),
                "holdme", new FixedCensor.Rule(CensorEngine.Decision.REVIEW, null, 0.55f)), clock);
    }

    public void authenticate() {
        admin().updateStanding(HubStanding.compute(0, 1, 0, null, false, HubPolicy.UnlockBasis.INBOUND_REQUIRED,
                clock.instant()));
    }

    public String newMember(org.shalim.identity.Role role) {
        String id = Fingerprints.signingKey(SoftwareSigner.generate().publicKey());
        admin().admit(admin.fingerprint(), id, org.shalim.identity.Role.MEMBER, null, null, null, false);
        if (role != org.shalim.identity.Role.MEMBER) {
            admin().assignRole(admin.fingerprint(), id, role);
        }
        return id;
    }
}
