package org.shalim.ml;

/**
 * Thrown when a model artefact cannot be loaded, verified, or run — no weights
 * on disk, hash mismatch, or insufficient memory.
 *
 * <p>Callers must decide explicitly what to do. For Matchmaker the answer is
 * degrade to keyword search; for the censor the answer is never "carry on
 * unscreened".
 */
public class ModelUnavailableException extends Exception {

    private static final long serialVersionUID = 1L;

    public enum Cause {
        NOT_DOWNLOADED,
        HASH_MISMATCH,
        SIGNATURE_INVALID,
        INSUFFICIENT_MEMORY,
        RUNTIME_ERROR,
        UNSUPPORTED_DEVICE
    }

    private final Cause cause;

    public ModelUnavailableException(Cause cause, String message) {
        super(message);
        this.cause = cause;
    }

    public Cause reason() {
        return cause;
    }

    /** Hash or signature failure means the artefact may have been tampered with. */
    public boolean indicatesTampering() {
        // TODO: pseudo-code
        return false;
    }
}
