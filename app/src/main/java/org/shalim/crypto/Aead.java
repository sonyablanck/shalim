package org.shalim.crypto;

import java.security.GeneralSecurityException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * ChaCha20-Poly1305 for data at rest: censor-log plaintext, the skills layer,
 * anything a seized device should not give up without its key.
 *
 * <p>Format: {@code 0x01 || nonce(12) || ciphertext+tag}. The nonce is random.
 * That is safe for about 2^32 messages under one key, many orders of magnitude
 * above a hub's fortnight of screenings. Keys should still be rotated with
 * each retention window, so that pruning a window and destroying its key go
 * together.
 *
 * <p>The associated data should name what the ciphertext is: which record,
 * which day, which index. A ciphertext moved to a different slot then fails
 * to open, instead of opening as the wrong record.
 */
public final class Aead {

    public static final int KEY_BYTES = 32;
    private static final int NONCE_BYTES = 12;
    private static final byte VERSION = 1;

    private Aead() {
    }

    public static byte[] newKey() {
        return Bytes.random(KEY_BYTES);
    }

    public static byte[] seal(byte[] key, byte[] plaintext, byte[] associatedData) {
        byte[] nonce = Bytes.random(NONCE_BYTES);
        byte[] ciphertext = chacha(Cipher.ENCRYPT_MODE, key, nonce, plaintext, associatedData);
        return Bytes.concat(new byte[] {VERSION}, nonce, ciphertext);
    }

    public static byte[] open(byte[] key, byte[] sealed, byte[] associatedData) {
        if (sealed == null || sealed.length < 1 + NONCE_BYTES + 16 || sealed[0] != VERSION) {
            throw new CryptoException("not a sealed record");
        }
        byte[] nonce = new byte[NONCE_BYTES];
        System.arraycopy(sealed, 1, nonce, 0, NONCE_BYTES);
        byte[] body = new byte[sealed.length - 1 - NONCE_BYTES];
        System.arraycopy(sealed, 1 + NONCE_BYTES, body, 0, body.length);
        return chacha(Cipher.DECRYPT_MODE, key, nonce, body, associatedData);
    }

    /**
     * ChaCha20-Poly1305 with a caller-supplied 96-bit nonce, for protocols that
     * derive nonces from counters (the transport's secure channel). Reusing a
     * nonce under one key reveals the XOR of two plaintexts and allows forgery,
     * so the caller must guarantee that a (key, nonce) pair is never used twice.
     */
    public static byte[] sealWithNonce(byte[] key, byte[] nonce, byte[] plaintext, byte[] associatedData) {
        requireNonce(nonce);
        return chacha(Cipher.ENCRYPT_MODE, key, nonce, plaintext, associatedData);
    }

    public static byte[] openWithNonce(byte[] key, byte[] nonce, byte[] ciphertext, byte[] associatedData) {
        requireNonce(nonce);
        return chacha(Cipher.DECRYPT_MODE, key, nonce, ciphertext, associatedData);
    }

    private static void requireNonce(byte[] nonce) {
        if (nonce == null || nonce.length != NONCE_BYTES) {
            throw new CryptoException("nonce must be 12 bytes");
        }
    }

    /** Raw ChaCha20-Poly1305 with a caller-supplied nonce. Package-private: nonce reuse is fatal. */
    static byte[] chacha(int mode, byte[] key, byte[] nonce, byte[] input, byte[] associatedData) {
        if (key == null || key.length != KEY_BYTES) {
            throw new CryptoException("ChaCha20-Poly1305 key must be 32 bytes");
        }
        try {
            Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
            cipher.init(mode, new SecretKeySpec(key, "ChaCha20"), new IvParameterSpec(nonce));
            if (associatedData != null) {
                cipher.updateAAD(associatedData);
            }
            return cipher.doFinal(input);
        } catch (javax.crypto.AEADBadTagException e) {
            throw new CryptoException("ciphertext did not authenticate", e);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("ChaCha20-Poly1305 failed", e);
        }
    }
}
