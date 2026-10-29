package org.shalim.hub;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.shalim.crypto.Bytes;
import org.shalim.crypto.Canonical;
import org.shalim.crypto.Prf;

/**
 * The network claims this device has pinned: one per hub it joined, like an
 * SSH known-hosts file.
 *
 * <h2>Why a device-local key</h2>
 *
 * <p>The pseudo-code had the creating device check "any pinned claim matches
 * the network". It could not: a pinned claim holds BSSID hashes keyed with the
 * <em>hub's</em> salt, which the device does not have, and must not have.
 * BSSIDs are 48 bits, so salt plus hashes would give up the building. So each
 * device keeps its own record. When it pins a hub, and whenever that hub later
 * answers a claim query on a new access point, the device stores
 * {@code HMAC(deviceKey, bssid)}. The key is a device secret, held in the
 * keystore on a phone. The pins can then answer "is this the network of a hub
 * I belong to?" on this device and nowhere else. A seized, locked phone gives
 * up nothing comparable. A seized, unlocked phone can test guessed BSSIDs one
 * at a time through the app, as it could by looking at the Wi-Fi settings.
 */
public final class ClaimPins {

    /** One pinned hub. */
    public static final class Pin {
        private final NetworkClaim claim;
        private final byte[] hubPublicKey;
        private final Set<String> localBssidHashes = new HashSet<>();
        private final Instant pinnedAt;

        Pin(NetworkClaim claim, byte[] hubPublicKey, Instant pinnedAt) {
            this.claim = claim;
            this.hubPublicKey = hubPublicKey.clone();
            this.pinnedAt = pinnedAt;
        }

        public NetworkClaim getClaim() {
            return claim;
        }

        public byte[] getHubPublicKey() {
            return hubPublicKey.clone();
        }

        public Instant getPinnedAt() {
            return pinnedAt;
        }
    }

    private final byte[] deviceKey;
    private final List<Pin> pins = new ArrayList<>();

    /** @param deviceKey a 32-byte device secret; never leaves the device */
    public ClaimPins(byte[] deviceKey) {
        this.deviceKey = deviceKey.clone();
    }

    /**
     * Pins a hub at join, from a verified answer to a claim query the device
     * just made on that hub's network. Replaces any earlier pin for the same
     * hub key.
     */
    public synchronized Pin pin(ClaimAnswer answer, byte[] nonce, String bssid, Instant now) {
        if (!answer.verify(nonce, bssid)) {
            return null;
        }
        pins.removeIf(p -> p.claim.getHubKeyFingerprint().equals(answer.hubKeyFingerprint()));
        Pin pin = new Pin(answer.toClaim(), answer.getHubPublicKey(), now);
        pin.localBssidHashes.add(localHash(bssid));
        pins.add(pin);
        return pin;
    }

    /**
     * Records another access point of a pinned hub, after that hub answered
     * for it. Answers from any other key are ignored.
     */
    public synchronized boolean observe(ClaimAnswer answer, byte[] nonce, String bssid) {
        Optional<Pin> pin = forHub(answer.hubKeyFingerprint());
        if (pin.isEmpty() || !answer.verify(nonce, bssid)) {
            return false;
        }
        return pin.get().localBssidHashes.add(localHash(bssid));
    }

    /**
     * Follows a signed migration from the pinned claim. The old access points
     * are forgotten, because the hub has said it left them.
     */
    public synchronized boolean follow(NetworkClaim migration, String newBssid) {
        for (Pin pin : pins) {
            if (pin.claim.isMigrationTo(migration, pin.hubPublicKey)) {
                Pin moved = new Pin(NetworkClaim.summary(migration.getClaimId(),
                        migration.getHubKeyFingerprint(), migration.getClaimedAt(),
                        migration.getSupersedesClaimId(), List.of()), pin.hubPublicKey, pin.pinnedAt);
                if (newBssid != null) {
                    moved.localBssidHashes.add(localHash(newBssid));
                }
                pins.remove(pin);
                pins.add(moved);
                return true;
            }
        }
        return false;
    }

    /** The pin, if any, covering any of these access points. */
    public synchronized Optional<Pin> matching(List<String> observedBssids) {
        for (String bssid : observedBssids) {
            if (Bssid.normalise(bssid) == null) {
                continue;
            }
            String h = localHash(bssid);
            for (Pin pin : pins) {
                if (pin.localBssidHashes.contains(h)) {
                    return Optional.of(pin);
                }
            }
        }
        return Optional.empty();
    }

    public synchronized Optional<Pin> forHub(String hubKeyFingerprint) {
        return pins.stream().filter(p -> p.claim.getHubKeyFingerprint().equals(hubKeyFingerprint)).findFirst();
    }

    public synchronized void unpin(String hubKeyFingerprint) {
        pins.removeIf(p -> p.claim.getHubKeyFingerprint().equals(hubKeyFingerprint));
    }

    public synchronized List<Pin> all() {
        return List.copyOf(pins);
    }

    /** Duress path. */
    public synchronized void wipe() {
        pins.clear();
        Bytes.wipe(deviceKey);
    }

    private String localHash(String bssid) {
        return Bytes.hex(Prf.hmac(deviceKey,
                Canonical.of("shalim.bssid.pin.v1").string(Bssid.normalise(bssid)).encode()));
    }
}
