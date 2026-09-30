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
        // TODO: pseudo-code
    }

    public ModelPin(Purpose purpose, String modelName, String version, String artefactHash) {
        // TODO: pseudo-code
    }

    /** Recomputes the hash of the artefact on disk and compares. */
    public boolean verifyArtefact(byte[] artefactBytes) {
        // TODO: pseudo-code
        return false;
    }

    /** Checks the release signature against a bundled public key. */
    public boolean verifySignature(byte[] releasePublicKey) {
        // TODO: pseudo-code
        return false;
    }

    /** Whether two hubs are running the same artefact. Used during sync. */
    public boolean matches(ModelPin other) {
        // TODO: pseudo-code
        return false;
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
}
