package org.shalim.ml;

import java.time.Instant;

/**
 * Identifies an exact model artefact by cryptographic hash.
 *
 * <p>This is the mechanism that makes "every hub censors identically" true
 * without a central server: hubs compare pins during sync, and a hub whose
 * censor artefact does not match the expected hash is treated as compromised.
 * Because verification is local, it survives a blackout and there is no
 * operator who can be compelled to ship a different model to one region.
 */
public class ModelPin {

    public enum Purpose {
        CENSOR,
        MATCHMAKER,
        EMBEDDING,
        /** The probe generator and divergence scorer. See {@link ProbeEngine}. */
        PROBER
    }

    private Purpose purpose;
    private String modelName;
    private String version;

    /** SHA-256 of the artefact. The identity that actually matters. */
    private String artefactHash;

    /** Detached signature from the release key, so a hash alone cannot be forged. */
    private String releaseSignature;

    private Instant pinnedAt;

    /** Quantisation and runtime, since these change outputs. */
    private String runtime;
    private String quantisation;

    public ModelPin() {
    }

    public ModelPin(Purpose purpose, String modelName, String version, String artefactHash) {
        this(purpose, modelName, version, artefactHash, null, null);
    }

    public ModelPin(Purpose purpose, String modelName, String version, String artefactHash,
                    String runtime, String quantisation) {
        this.purpose = purpose;
        this.modelName = modelName;
        this.version = version;
        this.artefactHash = artefactHash;
        this.runtime = runtime;
        this.quantisation = quantisation;
        this.pinnedAt = Instant.now();
    }

    /**
     * What the release key signs: {@code ("shalim.modelpin.v1", purpose,
     * name, version, artefactHash, runtime, quantisation)}. Runtime and
     * quantisation are included because they change outputs, and replay
     * depends on outputs being identical.
     */
    public byte[] signingPayload() {
        return org.shalim.crypto.Canonical.of("shalim.modelpin.v1").enumName(purpose)
                .string(modelName).string(version).hex(artefactHash).string(runtime)
                .string(quantisation).encode();
    }

    /** Release tooling only: signs this pin with the release key. */
    public ModelPin signWith(org.shalim.crypto.Signer releaseKey) {
        this.releaseSignature = releaseKey.signHex(signingPayload());
        return this;
    }

    /** Recomputes the hash of the artefact on disk and compares. */
    public boolean verifyArtefact(byte[] artefactBytes) {
        return artefactBytes != null && artefactHash != null && org.shalim.crypto.Bytes.equalHex(
                artefactHash, org.shalim.crypto.Hashing.sha256Hex(artefactBytes));
    }

    /** Checks the release signature against a bundled public key. */
    public boolean verifySignature(byte[] releasePublicKey) {
        return artefactHash != null
                && org.shalim.crypto.Ed25519.verifyHex(releasePublicKey, signingPayload(), releaseSignature);
    }

    /**
     * Whether two hubs are running the same artefact on the same runtime and
     * quantisation. Used during sync. Names and versions are labels and are
     * not compared; the hash is the identity.
     */
    public boolean matches(ModelPin other) {
        return other != null && purpose == other.purpose && artefactHash != null
                && org.shalim.crypto.Bytes.equalHex(artefactHash, other.artefactHash)
                && java.util.Objects.equals(runtime, other.runtime)
                && java.util.Objects.equals(quantisation, other.quantisation);
    }

    // --- accessors --------------------------------------------------------

    public Purpose getPurpose() {
        return purpose;
    }

    public String getModelName() {
        return modelName;
    }

    public String getVersion() {
        return version;
    }

    public String getArtefactHash() {
        return artefactHash;
    }

    public String getRuntime() {
        return runtime;
    }

    public String getQuantisation() {
        return quantisation;
    }

    public String getReleaseSignature() {
        return releaseSignature;
    }

    public Instant getPinnedAt() {
        return pinnedAt;
    }
}
