package org.shalim.crypto;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * In-memory key store. Nothing persists across restarts and nothing is
 * hardware-backed. For desktop development and tests only.
 */
public final class SoftwareAccountKeyStore implements AccountKeyStore {

    private final Map<String, SoftwareSigner> keys = new HashMap<>();

    @Override
    public synchronized boolean contains(String alias) {
        return keys.containsKey(alias);
    }

    @Override
    public synchronized Signer generate(String alias) {
        if (keys.containsKey(alias)) {
            throw new IllegalStateException("alias already holds a key: " + alias);
        }
        SoftwareSigner signer = SoftwareSigner.generate();
        keys.put(alias, signer);
        return signer;
    }

    @Override
    public synchronized Optional<Signer> load(String alias) {
        return Optional.ofNullable(keys.get(alias));
    }

    @Override
    public synchronized void destroy(String alias) {
        keys.remove(alias);
    }

    @Override
    public boolean isHardwareBacked() {
        return false;
    }
}
