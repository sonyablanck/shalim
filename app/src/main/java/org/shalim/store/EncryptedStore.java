package org.shalim.store;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;
import org.shalim.crypto.Aead;
import org.shalim.crypto.Bytes;
import org.shalim.crypto.Canonical;
import org.shalim.crypto.CryptoException;

/**
 * Named records, encrypted at rest, in one directory. Where a hub instance
 * keeps its state between runs.
 *
 * <h2>Layout</h2>
 * <pre>
 *   store.key      Aead(kek, dataKey, aad = "shalim.store.key.v1")
 *   NAME.rec       Aead(dataKey, record, aad = ("shalim.store.record.v1", NAME))
 * </pre>
 * Record names are bound into the encryption, so one record's file cannot be
 * renamed into another's place. Writes go to a temporary file and are then
 * moved into place, so a crash leaves the old record or the new one, never
 * half of each.
 *
 * <h2>Shredding</h2>
 *
 * <p>Deleting a file on flash storage does not erase it: wear-levelling keeps
 * old blocks around, and forensic tools read them. {@link #shred()} therefore
 * destroys the one small thing everything depends on, the wrapped data key,
 * by overwriting it in place and deleting it, and only then deletes the
 * records. If any block of a record survives, it is ciphertext under a key
 * that no longer exists anywhere. If the key file's own old blocks survive,
 * they are wrapped under the passphrase or keystore key, which is why the
 * passphrase still matters after a wipe. That is the residual risk, and it is
 * stated in the README.
 */
public final class EncryptedStore {

    private static final Pattern NAME = Pattern.compile("[a-z0-9][a-z0-9._-]{0,63}");
    private static final String KEY_FILE = "store.key";
    private static final byte[] KEY_AAD = "shalim.store.key.v1".getBytes(StandardCharsets.US_ASCII);

    private final Path dir;
    private byte[] dataKey;

    private EncryptedStore(Path dir, byte[] dataKey) {
        this.dir = dir;
        this.dataKey = dataKey;
    }

    /**
     * Opens the store in {@code dir}, creating it with a fresh data key if
     * there is none. Throws {@link CryptoException} if the key-encryption key
     * is wrong.
     */
    public static EncryptedStore open(Path dir, byte[] keyEncryptionKey) {
        try {
            Files.createDirectories(dir);
            Path keyFile = dir.resolve(KEY_FILE);
            if (Files.exists(keyFile)) {
                byte[] dataKey = Aead.open(keyEncryptionKey, Files.readAllBytes(keyFile), KEY_AAD);
                return new EncryptedStore(dir, dataKey);
            }
            byte[] dataKey = Aead.newKey();
            writeAtomically(dir, keyFile, Aead.seal(keyEncryptionKey, dataKey, KEY_AAD));
            return new EncryptedStore(dir, dataKey);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** Rewraps the data key under a new key-encryption key, e.g. after a passphrase change. */
    public synchronized void rewrap(byte[] newKeyEncryptionKey) {
        requireOpen();
        try {
            writeAtomically(dir, dir.resolve(KEY_FILE), Aead.seal(newKeyEncryptionKey, dataKey, KEY_AAD));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public synchronized void put(String name, byte[] record) {
        requireOpen();
        checkName(name);
        try {
            writeAtomically(dir, dir.resolve(name + ".rec"), Aead.seal(dataKey, record, aad(name)));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** The record, or empty if absent. Throws if it exists but does not authenticate. */
    public synchronized Optional<byte[]> get(String name) {
        requireOpen();
        checkName(name);
        Path p = dir.resolve(name + ".rec");
        if (!Files.exists(p)) {
            return Optional.empty();
        }
        try {
            return Optional.of(Aead.open(dataKey, Files.readAllBytes(p), aad(name)));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public synchronized boolean delete(String name) {
        checkName(name);
        try {
            return Files.deleteIfExists(dir.resolve(name + ".rec"));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public synchronized List<String> names() {
        List<String> out = new ArrayList<>();
        try (DirectoryStream<Path> files = Files.newDirectoryStream(dir, "*.rec")) {
            for (Path p : files) {
                String f = p.getFileName().toString();
                out.add(f.substring(0, f.length() - 4));
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        out.sort(null);
        return out;
    }

    /**
     * Crypto-shred: destroys the key first, then the records. Irreversible. The
     * store is closed afterwards; every further call throws.
     */
    public synchronized void shred() {
        try {
            Path keyFile = dir.resolve(KEY_FILE);
            if (Files.exists(keyFile)) {
                long size = Files.size(keyFile);
                Files.write(keyFile, Bytes.random((int) Math.max(size, 64)));
                Files.delete(keyFile);
            }
            Bytes.wipe(dataKey);
            dataKey = null;
            try (DirectoryStream<Path> files = Files.newDirectoryStream(dir, "*.{rec,tmp}")) {
                for (Path p : files) {
                    Files.deleteIfExists(p);
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public boolean isOpen() {
        return dataKey != null;
    }

    private void requireOpen() {
        if (dataKey == null) {
            throw new IllegalStateException("store has been shredded");
        }
    }

    private static void checkName(String name) {
        if (name == null || !NAME.matcher(name).matches() || name.equals("store")) {
            throw new IllegalArgumentException("record names are lower-case letters, digits, '.', '_' and '-'");
        }
    }

    private static byte[] aad(String name) {
        return Canonical.of("shalim.store.record.v1").string(name).encode();
    }

    private static void writeAtomically(Path dir, Path target, byte[] bytes) throws IOException {
        Path tmp = Files.createTempFile(dir, ".write-", ".tmp");
        try {
            Files.write(tmp, bytes);
            try {
                Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(tmp);
        }
    }
}
