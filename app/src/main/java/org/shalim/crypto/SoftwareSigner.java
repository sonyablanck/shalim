package org.shalim.crypto;

import java.security.KeyPair;
import java.security.PrivateKey;

/**
 * An Ed25519 key held in process memory. Fine for hub instances on a desktop
 * and for tests. A user account on a phone should use a hardware-backed
 * {@link AccountKeyStore} instead.
 */
public final class SoftwareSigner implements Signer {

    private final PrivateKey privateKey;
    private final byte[] publicKey;

    private SoftwareSigner(KeyPair pair) {
        this.privateKey = pair.getPrivate();
        this.publicKey = Ed25519.rawPublicKey(pair.getPublic());
    }

    public static SoftwareSigner generate() {
        return new SoftwareSigner(Ed25519.generate());
    }

    public static SoftwareSigner fromSeed(byte[] seed) {
        return new SoftwareSigner(Ed25519.fromSeed(seed));
    }

    @Override
    public byte[] publicKey() {
        return publicKey.clone();
    }

    @Override
    public byte[] sign(byte[] message) {
        return Ed25519.sign(privateKey, message);
    }
}
