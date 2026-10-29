package org.shalim.identity;

import java.time.Instant;
import org.shalim.crypto.Fingerprints;
import org.shalim.crypto.Signer;
import org.shalim.crypto.SoftwareAccountKeyStore;
import org.shalim.crypto.SoftwareSigner;
import org.shalim.testing.Check;

public final class IdentityTest {

    private static final Instant NOW = Instant.parse("2026-10-29T09:00:00Z");

    private IdentityTest() {
    }

    public static void testUserIdIsTheKeyFingerprintAndSigningWorks() {
        DeviceBinding device = new DeviceBinding(new SoftwareAccountKeyStore());
        Signer key = device.bind(DeviceBinding.Slot.REGISTERED, NOW);
        RegisteredUser me = new RegisteredUser(key, "Dana");
        Check.equal(key.fingerprint(), me.getUserId(), "user id = fingerprint");
        Check.equal(me.getUserId(), device.getAccountKeyFingerprint(), "slot records the same key");
        byte[] payload = {1, 2, 3};
        Check.isTrue(me.verify(payload, me.sign(payload)), "own signature verifies");
    }

    public static void testOneAccountPerDevice() {
        DeviceBinding device = new DeviceBinding(new SoftwareAccountKeyStore());
        Check.notNull(device.bind(DeviceBinding.Slot.REGISTERED, NOW), "first account");
        Check.isNull(device.bind(DeviceBinding.Slot.REGISTERED, NOW), "second account refused");
        Check.isNull(device.bind(DeviceBinding.Slot.GUEST, NOW), "guest alongside account refused");
        device.release();
        Check.equal(DeviceBinding.Slot.EMPTY, device.getSlot(), "released");
        Check.notNull(device.bind(DeviceBinding.Slot.REGISTERED, NOW), "slot reusable after release");
    }

    public static void testGuestUpgradesInPlaceKeepingItsKey() {
        DeviceBinding device = new DeviceBinding(new SoftwareAccountKeyStore());
        Signer guestKey = device.bind(DeviceBinding.Slot.GUEST, NOW);
        GuestUser guest = new GuestUser(guestKey, "walk-in", "hub-1", NOW.plusSeconds(3600));
        Check.isFalse(guest.isExpired(NOW), "not yet expired");
        Check.isTrue(guest.isExpired(NOW.plusSeconds(3600)), "expired at expiresAt");
        Check.isNull(device.bind(DeviceBinding.Slot.GUEST, NOW), "no second guest");
        RegisteredUser upgraded = guest.upgrade(device, NOW);
        Check.notNull(upgraded, "upgraded");
        Check.equal(guest.getUserId(), upgraded.getUserId(), "same identity");
        Check.equal(DeviceBinding.Slot.REGISTERED, device.getSlot(), "slot now registered");
        Check.isFalse(upgraded.isProvisional(), "no longer provisional");
    }

    public static void testRecordOfSomeoneElseCannotSignAndOnlyAcceptsTheirKey() {
        SoftwareSigner theirs = SoftwareSigner.generate();
        RegisteredUser them = new RegisteredUser(theirs.fingerprint(), "them");
        Check.isFalse(them.canSign(), "no private key here");
        Check.throwsA(IllegalStateException.class, () -> them.sign(new byte[1]), "cannot sign");
        Check.isFalse(them.withPublicKey(SoftwareSigner.generate().publicKey()), "wrong key refused");
        Check.isTrue(them.withPublicKey(theirs.publicKey()), "their key accepted");
        byte[] payload = {9};
        Check.isTrue(them.verify(payload, theirs.sign(payload)), "verifies their signature");
        Check.isTrue(Fingerprints.matchesSigningKey(them.getUserId(), them.publicKey()), "consistent");
    }

    public static void testAttestationFailsClosedUntilImplemented() {
        Check.isFalse(DeviceBinding.verifyAttestation(java.util.List.of(), new byte[8], "fp",
                java.util.List.of(), java.util.List.of()), "no member counts as attested yet");
        DeviceBinding device = new DeviceBinding(new SoftwareAccountKeyStore());
        device.bind(DeviceBinding.Slot.REGISTERED, NOW);
        Check.isFalse(device.canAttest(), "software keys cannot attest");
    }
}
