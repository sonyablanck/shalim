package org.shalim.crypto;

/**
 * Stable names for public keys: SHA-256 over a tagged encoding of the key,
 * as hex.
 *
 * <p>Signing keys and encryption keys get different tags. So a fingerprint
 * always says which kind of key it names, and the same 32 bytes used as both
 * kinds would not collide. This is the {@code userId} and the
 * {@code ...KeyFingerprint} used throughout the codebase.
 */
public final class Fingerprints {

    private Fingerprints() {
    }

    public static String signingKey(byte[] rawEd25519PublicKey) {
        return Canonical.of("shalim.fp.ed25519.v1").bytes(rawEd25519PublicKey).digestHex();
    }

    public static String encryptionKey(byte[] rawX25519PublicKey) {
        return Canonical.of("shalim.fp.x25519.v1").bytes(rawX25519PublicKey).digestHex();
    }

    /** Whether a public key is the one a fingerprint names. */
    public static boolean matchesSigningKey(String fingerprint, byte[] rawEd25519PublicKey) {
        return rawEd25519PublicKey != null
                && Bytes.equalHex(fingerprint, signingKey(rawEd25519PublicKey));
    }
}
