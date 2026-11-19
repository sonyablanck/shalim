package org.shalim.attestation;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.shalim.crypto.SoftwareSigner;
import org.shalim.hub.HubPolicy;
import org.shalim.identity.Restriction;
import org.shalim.identity.Role;
import org.shalim.testing.Check;
import org.shalim.testing.HubFixture;

public final class AttestationFlowTest {

    private AttestationFlowTest() {
    }

    public static void testGoodStandingIsWithheldWhileTheHubIsFlagged() {
        HubFixture f = new HubFixture();
        String member = f.newMember(Role.MEMBER);
        AttestationIssuer issuer = new AttestationIssuer(f.hub, f.hubKey);
        Attestation a = issuer.issueGoodStanding(member, f.clock.instant());
        Check.notNull(a, "issued");
        Check.isTrue(a.verify(f.hubKey.publicKey()), "signed by the hub");
        Check.isNull(issuer.issueGoodStanding("stranger", f.clock.instant()), "only for members");
        f.censor.simulateTampering();
        f.admin().checkCensorIntegrity(f.clock.instant());
        Check.isFalse(issuer.canIssue(), "a flagged hub cannot vouch");
        Check.isNull(issuer.issueGoodStanding(member, f.clock.instant()), "so the member's proof simply lapses");
    }

    public static void testOutcomesAreLocalUnlessFederatedAndNeverExportedUnderAppeal() {
        HubFixture f = new HubFixture();
        f.authenticate();
        String mod = f.newMember(Role.MODERATOR);
        String member = f.newMember(Role.MEMBER);
        String evidence = f.hub.getLog().getHeadHash();
        Instant now = f.clock.instant();
        ModerationOutcome o = new ModerationOutcome(member, f.hubKey.fingerprint(), ModerationOutcome.Kind.REMOVAL,
                ModerationOutcome.Ground.REPEATED_UNWANTED_CONTACT, mod, now, now.plus(Duration.ofDays(90)),
                List.of(evidence));
        Check.isTrue(f.admin().recordOutcome(mod, o), "recorded");
        Check.isFalse(f.hub.getRoster().membershipOf(member).get().can(org.shalim.identity.Permission.RUN_HUB_QUERY,
                f.hub.getStanding()), "and capped here at once");
        AttestationIssuer issuer = new AttestationIssuer(f.hub, f.hubKey);
        Check.isNull(issuer.issueGoodStanding(member, now), "no good standing with an active outcome");
        Check.isNull(issuer.issueOutcomeAttestation(o, now), "not federatable by default");
        f.admin().changePolicy(f.admin.fingerprint(), p -> p.setFederateModerationOutcomes(true));
        o.setFederatable(true);
        Check.notNull(issuer.issueOutcomeAttestation(o, now), "shareable once both hub and outcome say so");
        Check.isTrue(f.admin().appealOutcome(member, o.getOutcomeId()), "appealed by the subject");
        Check.isNull(issuer.issueOutcomeAttestation(o, now), "not exported while contested");
        Check.isFalse(f.admin().overturnOutcome(mod, o.getOutcomeId(), "on reflection"),
                "not overturned by the moderator who decided it");
        Check.isTrue(f.admin().overturnOutcome(f.admin.fingerprint(), o.getOutcomeId(), "insufficient evidence"),
                "overturned by someone else");
        Check.isTrue(f.hub.getRoster().membershipOf(member).get().can(org.shalim.identity.Permission.RUN_HUB_QUERY,
                f.hub.getStanding()), "and the cap lifts");
        Check.throwsA(IllegalArgumentException.class, () -> new ModerationOutcome(member, "x",
                ModerationOutcome.Kind.WARNING, ModerationOutcome.Ground.OTHER, mod, now, now.plus(Duration.ofDays(400)),
                List.of(evidence)), "nothing lasts more than a year");
    }

    public static void testReceivingHubFailsOpenInABlackout() {
        SoftwareSigner issuerKey = SoftwareSigner.generate();
        SoftwareSigner subject = SoftwareSigner.generate();
        Instant now = Instant.parse("2026-11-18T10:00:00Z");
        HubPolicy strict = HubPolicy.defaultsFor(HubPolicy.Posture.COMMUNITY);
        strict.setRequireGoodStanding(true);
        AttestationVerifier v = new AttestationVerifier("library", strict, List.of(issuerKey.fingerprint()),
                Map.of(issuerKey.fingerprint(), issuerKey.publicKey())::get);
        AttestationWallet empty = new AttestationWallet(subject.fingerprint());
        Check.isNull(v.evaluate(empty, "m", false, now), "no proof, no way to refresh: no cap");
        Restriction capped = v.evaluate(empty, "m", true, now);
        Check.equal(Role.GUEST, capped.getRoleCap(), "no proof while refresh is possible: guest");
        Check.isTrue(capped.getExplanation().contains("cannot currently vouch"), "and told why, without naming a hub");

        AttestationWallet wallet = new AttestationWallet(subject.fingerprint());
        wallet.store(Attestation.issue(Attestation.Claim.GOOD_STANDING, subject.fingerprint(), issuerKey, now,
                now.plus(Duration.ofDays(3)), null));
        Check.isNull(v.evaluate(wallet, "m", true, now), "a valid proof: no cap");
        Check.equal(Role.MODERATOR, v.permittedRole(wallet, Role.MODERATOR, true, now), "role as requested");
        wallet.store(Attestation.issue(Attestation.Claim.GOOD_STANDING, SoftwareSigner.generate().fingerprint(),
                issuerKey, now, now.plus(Duration.ofDays(3)), null));
        Check.equal(1, wallet.size(), "a wallet refuses someone else's proof");
        Check.equal(1, wallet.forgetIssuer(issuerKey.fingerprint()), "leaving drops that hub's proofs");
        Check.equal(AttestationVerifier.Outcome.INVALID, v.verify(Attestation.issue(Attestation.Claim.GOOD_STANDING,
                SoftwareSigner.generate().fingerprint(), issuerKey, now, now.plusSeconds(60), null),
                subject.fingerprint(), now),
                "a proof for someone else is a replay");
    }
}
