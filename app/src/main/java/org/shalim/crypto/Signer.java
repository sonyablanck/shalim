package org.shalim.crypto;

/**
 * Something that can sign with a private key it never hands out. Account keys
 * sit behind this in the device keystore, and hub issuer keys in the hub
 * runtime. State classes never hold one. Methods that need to sign take it as
 * an argument, so hub state stays plain data: services depend on state, and
 * state never depends on services.
 */
public interface Signer {

    /** Raw 32-byte Ed25519 public key. */
    byte[] publicKey();

    byte[] sign(byte[] message);

    default String fingerprint() {
        return Fingerprints.signingKey(publicKey());
    }

    default String signHex(byte[] message) {
        return Bytes.hex(sign(message));
    }
}
