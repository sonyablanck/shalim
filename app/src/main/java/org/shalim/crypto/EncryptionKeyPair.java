package org.shalim.crypto;

import java.security.KeyPair;
import java.security.PrivateKey;

/**
 * An X25519 key pair that things can be sealed to: a hub's replay key, for
 * example, which peers encrypt opened leaves to. It is kept separate from the
 * hub's Ed25519 issuer key. Using one key for both signing and encryption
 * invites cross-protocol attacks, and keeping them apart lets the encryption
 * key be rotated without re-establishing the hub's identity.
 */
public final class EncryptionKeyPair {

    private final PrivateKey privateKey;
    private final byte[] publicKey;

    private EncryptionKeyPair(PrivateKey privateKey, byte[] publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    public static EncryptionKeyPair generate() {
        KeyPair pair = X25519.generate();
        return new EncryptionKeyPair(pair.getPrivate(), X25519.rawPublicKey(pair.getPublic()));
    }

    public static EncryptionKeyPair fromPrivate(byte[] scalar) {
        PrivateKey key = X25519.privateKeyFromRaw(scalar);
        return new EncryptionKeyPair(key, X25519.publicFromPrivate(key));
    }

    public byte[] publicKey() {
        return publicKey.clone();
    }

    public String fingerprint() {
        return Fingerprints.encryptionKey(publicKey);
    }

    byte[] agree(byte[] peerRawPublicKey) {
        return X25519.agree(privateKey, peerRawPublicKey);
    }

    PrivateKey privateKey() {
        return privateKey;
    }
}
