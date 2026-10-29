package org.shalim.crypto;

/**
 * A primitive failed: a ciphertext did not authenticate, a key was malformed,
 * or the platform lacks an algorithm. Verification methods return
 * {@code false} instead of throwing. Only operations that cannot sensibly
 * return a value (decrypting, deriving) throw this.
 */
public class CryptoException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public CryptoException(String message) {
        super(message);
    }

    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}
