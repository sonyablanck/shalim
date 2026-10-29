package org.shalim.crypto;

import java.util.Optional;

/**
 * Where a device keeps its account key. On Android this will be the
 * hardware-backed Android Keystore (StrongBox or TEE); on iOS, the Secure
 * Enclave. Keys made there cannot be exported, so a {@link Signer} handle is
 * all the app ever holds.
 *
 * <p>{@link SoftwareAccountKeyStore} is the only implementation so far. It is
 * for desktops and tests, and it says so through {@link #isHardwareBacked()}.
 */
public interface AccountKeyStore {

    boolean contains(String alias);

    /** Makes a new key under {@code alias}. Fails if the alias is taken. */
    Signer generate(String alias);

    Optional<Signer> load(String alias);

    /** Destroys the key. Irreversible. */
    void destroy(String alias);

    /**
     * Whether keys here are non-exportable hardware keys. Only such keys can
     * produce the key attestation that lets a member act as a prober.
     */
    boolean isHardwareBacked();
}
