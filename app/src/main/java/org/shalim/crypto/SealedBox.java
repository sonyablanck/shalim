package org.shalim.crypto;

import java.security.KeyPair;
import java.security.PrivateKey;
import javax.crypto.Cipher;

/**
 * Anonymous-sender encryption to an X25519 public key: what a peer uses to
 * send an auditor the plaintext of an opened leaf, readable by that auditor
 * only.
 *
 * <p>Construction, in the shape of HPKE base mode (RFC 9180) but not
 * wire-compatible with it:
 * <pre>
 *   e, E   = fresh X25519 key pair
 *   dh     = X25519(e, R)                          R = recipient public key
 *   okm    = HKDF-SHA256(salt = E || R, ikm = dh,
 *                        info = "shalim.sealedbox.v1", 44 bytes)
 *   key    = okm[0..32), nonce = okm[32..44)
 *   output = 0x01 || E || ChaCha20-Poly1305(key, nonce, aad, plaintext)
 * </pre>
 * Every message has a fresh ephemeral key, so key and nonce are never reused.
 * Binding E and R into the derivation stops a ciphertext being re-targeted.
 * There is no sender authentication. Where the sender matters, as with leaf
 * openings, the content is separately bound to a signed record.
 */
public final class SealedBox {

    private static final byte VERSION = 1;
    private static final byte[] INFO = "shalim.sealedbox.v1".getBytes(java.nio.charset.StandardCharsets.US_ASCII);

    private SealedBox() {
    }

    public static byte[] seal(byte[] recipientPublicKey, byte[] plaintext, byte[] associatedData) {
        KeyPair ephemeral = X25519.generate();
        byte[] ephemeralPublic = X25519.rawPublicKey(ephemeral.getPublic());
        byte[] okm = derive(ephemeral.getPrivate(), recipientPublicKey, ephemeralPublic, recipientPublicKey);
        try {
            byte[] ciphertext = Aead.chacha(Cipher.ENCRYPT_MODE, slice(okm, 0, 32), slice(okm, 32, 12),
                    plaintext, associatedData);
            return Bytes.concat(new byte[] {VERSION}, ephemeralPublic, ciphertext);
        } finally {
            Bytes.wipe(okm);
        }
    }

    public static byte[] open(EncryptionKeyPair recipient, byte[] sealed, byte[] associatedData) {
        if (sealed == null || sealed.length < 1 + X25519.KEY_BYTES + 16 || sealed[0] != VERSION) {
            throw new CryptoException("not a sealed box");
        }
        byte[] ephemeralPublic = slice(sealed, 1, X25519.KEY_BYTES);
        byte[] body = slice(sealed, 1 + X25519.KEY_BYTES, sealed.length - 1 - X25519.KEY_BYTES);
        byte[] okm = derive(recipient.privateKey(), ephemeralPublic, ephemeralPublic, recipient.publicKey());
        try {
            return Aead.chacha(Cipher.DECRYPT_MODE, slice(okm, 0, 32), slice(okm, 32, 12), body,
                    associatedData);
        } finally {
            Bytes.wipe(okm);
        }
    }

    private static byte[] derive(PrivateKey own, byte[] peerPublic, byte[] ephemeralPublic,
                                 byte[] recipientPublic) {
        byte[] dh = X25519.agree(own, peerPublic);
        try {
            return Hkdf.derive(Bytes.concat(ephemeralPublic, recipientPublic), dh, INFO, 44);
        } finally {
            Bytes.wipe(dh);
        }
    }

    private static byte[] slice(byte[] in, int from, int length) {
        byte[] out = new byte[length];
        System.arraycopy(in, from, out, 0, length);
        return out;
    }
}
