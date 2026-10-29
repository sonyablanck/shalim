package org.shalim.records;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import org.shalim.attestation.Attestation;
import org.shalim.crypto.Hashing;
import org.shalim.crypto.SoftwareSigner;
import org.shalim.ml.ModelPin;
import org.shalim.testing.Check;
import org.shalim.trust.ProbeCorpus;

/** Release-signed pins and hub-signed attestations. */
public final class SignedRecordsTest {

    private static final Instant NOW = Instant.parse("2026-10-29T09:00:00Z");

    private SignedRecordsTest() {
    }

    public static void testModelPinVerifiesArtefactAndReleaseSignature() {
        byte[] artefact = "pretend weights".getBytes(StandardCharsets.UTF_8);
        SoftwareSigner release = SoftwareSigner.generate();
        ModelPin pin = new ModelPin(ModelPin.Purpose.CENSOR, "TinyCensor", "1.0",
                Hashing.sha256Hex(artefact), "cpu-ref", "int8").signWith(release);
        Check.isTrue(pin.verifyArtefact(artefact), "artefact matches");
        Check.isFalse(pin.verifyArtefact("other".getBytes(StandardCharsets.UTF_8)), "other artefact");
        Check.isTrue(pin.verifySignature(release.publicKey()), "release signature");
        Check.isFalse(pin.verifySignature(SoftwareSigner.generate().publicKey()), "not another key");

        ModelPin sameHashOtherRuntime = new ModelPin(ModelPin.Purpose.CENSOR, "TinyCensor", "1.0",
                Hashing.sha256Hex(artefact), "nnapi", "int8");
        Check.isFalse(pin.matches(sameHashOtherRuntime), "runtime changes outputs, so it must match too");
        ModelPin relabelled = new ModelPin(ModelPin.Purpose.CENSOR, "Renamed", "9.9",
                Hashing.sha256Hex(artefact), "cpu-ref", "int8");
        Check.isTrue(pin.matches(relabelled), "labels do not matter, the hash does");
        Check.isFalse(relabelled.verifySignature(release.publicKey()),
                "but a relabelled pin no longer carries the release signature");
    }

    public static void testProbeCorpusVerifies() {
        byte[] corpus = "{\"probes\":[]}".getBytes(StandardCharsets.UTF_8);
        SoftwareSigner release = SoftwareSigner.generate();
        ProbeCorpus pinned = new ProbeCorpus("2026.10", Hashing.sha256Hex(corpus)).signWith(release);
        Check.isTrue(pinned.verify(corpus, release.publicKey()), "verifies");
        Check.isFalse(pinned.verify("{}".getBytes(StandardCharsets.UTF_8), release.publicKey()), "other bytes");
        Check.isTrue(pinned.matches(new ProbeCorpus("2026.10", Hashing.sha256Hex(corpus))), "same corpus");
    }

    public static void testAttestationSignatureValidityAndRefresh() {
        SoftwareSigner hub = SoftwareSigner.generate();
        String subject = SoftwareSigner.generate().fingerprint();
        Attestation a = Attestation.issue(Attestation.Claim.GOOD_STANDING, subject, hub, NOW,
                NOW.plus(Duration.ofDays(4)), null);
        Check.isTrue(a.verify(hub.publicKey()), "verifies");
        Check.isFalse(a.verify(SoftwareSigner.generate().publicKey()), "not under another key");
        Check.isTrue(a.isValid(NOW.plus(Duration.ofDays(1))), "valid mid-window");
        Check.isTrue(a.isValid(NOW.minus(Duration.ofMinutes(2))), "tolerates small clock skew");
        Check.isFalse(a.isValid(NOW.plus(Duration.ofDays(4))), "expired at expiresAt");
        Check.isFalse(a.needsRefresh(NOW.plus(Duration.ofDays(2))), "not yet");
        Check.isTrue(a.needsRefresh(NOW.plus(Duration.ofDays(3))), "last quarter");

        Attestation upgraded = Attestation.received(a.getAttestationId(), Attestation.Claim.ADULT, subject,
                a.getIssuerKeyFingerprint(), a.getIssuedAt(), a.getExpiresAt(), null, a.getSignature());
        Check.isFalse(upgraded.verify(hub.publicKey()), "claim cannot be swapped under the signature");
        Attestation extended = Attestation.received(a.getAttestationId(), a.getClaim(), subject,
                a.getIssuerKeyFingerprint(), a.getIssuedAt(), a.getExpiresAt().plus(Duration.ofDays(30)), null,
                a.getSignature());
        Check.isFalse(extended.verify(hub.publicKey()), "expiry cannot be extended");
    }
}
