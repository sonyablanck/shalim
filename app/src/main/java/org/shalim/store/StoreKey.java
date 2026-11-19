package org.shalim.store;

import java.security.GeneralSecurityException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.shalim.crypto.Bytes;
import org.shalim.crypto.CryptoException;

/**
 * Key-encryption keys for an {@link EncryptedStore}: the key that wraps the
 * store's own data key, never the data key itself.
 *
 * <ul>
 *   <li>{@link #fromPassphrase}: PBKDF2-HMAC-SHA256 with 600,000 iterations,
 *       the OWASP figure for that function. On a desktop hub that is the
 *       admin's passphrase. Slow by design.</li>
 *   <li>{@link #random}: a device secret, for a phone where the platform
 *       keystore wraps it instead (stage 7).</li>
 * </ul>
 *
 * <p>Changing the passphrase rewraps one 32-byte data key and nothing else.
 */
public final class StoreKey {

    public static final int ITERATIONS = 600_000;
    public static final int SALT_BYTES = 16;

    private StoreKey() {
    }

    public static byte[] random() {
        return Bytes.random(32);
    }

    public static byte[] newSalt() {
        return Bytes.random(SALT_BYTES);
    }

    public static byte[] fromPassphrase(char[] passphrase, byte[] salt) {
        return fromPassphrase(passphrase, salt, ITERATIONS);
    }

    /** Fewer iterations are for tests only. */
    public static byte[] fromPassphrase(char[] passphrase, byte[] salt, int iterations) {
        if (passphrase == null || passphrase.length == 0 || salt == null || salt.length < SALT_BYTES) {
            throw new CryptoException("a passphrase and a 16-byte salt are required");
        }
        PBEKeySpec spec = new PBEKeySpec(passphrase, salt, iterations, 256);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } catch (InvalidKeySpecException e) {
            throw new CryptoException("bad passphrase parameters", e);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("PBKDF2 unavailable", e);
        } finally {
            spec.clearPassword();
        }
    }
}
