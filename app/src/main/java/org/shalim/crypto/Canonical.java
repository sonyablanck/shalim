package org.shalim.crypto;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * The one encoding used for everything that is hashed or signed.
 *
 * <p>A record starts with a domain tag such as {@code "shalim.cdl.leaf.v1"}.
 * After it, every field is one type byte, a four-byte big-endian length and
 * the value. So:
 * <ul>
 *   <li>no two different field sequences encode to the same bytes, which
 *       naive concatenation like {@code H(a || b)} does not guarantee;</li>
 *   <li>null and empty are different;</li>
 *   <li>a signature made over one kind of record can never verify as another,
 *       because the domain tags differ;</li>
 *   <li>bumping the version in a tag retires every old signature of that kind
 *       at once.</li>
 * </ul>
 *
 * <p>Lists of strings are sorted before encoding, because every list signed
 * in this design is a set (categories, BSSID hashes). Use
 * {@link #orderedStrings} where order carries meaning.
 */
public final class Canonical {

    private static final byte NULL = 0;
    private static final byte BYTES = 1;
    private static final byte STRING = 2;
    private static final byte LONG = 3;
    private static final byte BOOL = 4;
    private static final byte INSTANT = 5;
    private static final byte DATE = 6;
    private static final byte FLOAT = 7;
    private static final byte LIST = 8;

    private final ByteArrayOutputStream out = new ByteArrayOutputStream();

    private Canonical(String domain) {
        if (domain == null || domain.isEmpty()) {
            throw new IllegalArgumentException("domain tag required");
        }
        string(domain);
    }

    public static Canonical of(String domain) {
        return new Canonical(domain);
    }

    public Canonical bytes(byte[] value) {
        return value == null ? field(NULL, new byte[0]) : field(BYTES, value);
    }

    public Canonical string(String value) {
        return value == null ? field(NULL, new byte[0])
                : field(STRING, value.getBytes(StandardCharsets.UTF_8));
    }

    /** Hex text is encoded as the bytes it denotes, so case cannot matter. */
    public Canonical hex(String value) {
        return value == null ? field(NULL, new byte[0]) : field(BYTES, Bytes.fromHex(value));
    }

    public Canonical u64(long value) {
        return field(LONG, longBytes(value));
    }

    public Canonical bool(boolean value) {
        return field(BOOL, new byte[] {(byte) (value ? 1 : 0)});
    }

    public Canonical instant(Instant value) {
        if (value == null) {
            return field(NULL, new byte[0]);
        }
        return field(INSTANT, Bytes.concat(longBytes(value.getEpochSecond()),
                intBytes(value.getNano())));
    }

    public Canonical date(LocalDate value) {
        return value == null ? field(NULL, new byte[0]) : field(DATE, longBytes(value.toEpochDay()));
    }

    /** By bit pattern, so 0.1f always encodes the same way on every device. */
    public Canonical f32(float value) {
        return field(FLOAT, intBytes(Float.floatToIntBits(value)));
    }

    public Canonical enumName(Enum<?> value) {
        return string(value == null ? null : value.name());
    }

    /** A set of strings: sorted, then encoded. Null and empty differ. */
    public Canonical strings(Collection<String> values) {
        if (values == null) {
            return field(NULL, new byte[0]);
        }
        List<String> sorted = new ArrayList<>(values);
        sorted.sort(null);
        return orderedStrings(sorted);
    }

    public Canonical orderedStrings(List<String> values) {
        if (values == null) {
            return field(NULL, new byte[0]);
        }
        Canonical inner = new Canonical("list");
        for (String value : values) {
            inner.string(value);
        }
        return field(LIST, inner.encode());
    }

    /** A set of enum constants, by name. */
    public Canonical enumSet(Collection<? extends Enum<?>> values) {
        if (values == null) {
            return field(NULL, new byte[0]);
        }
        List<String> names = new ArrayList<>();
        for (Enum<?> value : values) {
            names.add(value.name());
        }
        return strings(names);
    }

    public byte[] encode() {
        return out.toByteArray();
    }

    /** SHA-256 of the encoding. */
    public byte[] digest() {
        return Hashing.sha256(encode());
    }

    public String digestHex() {
        return Bytes.hex(digest());
    }

    private Canonical field(byte type, byte[] value) {
        out.write(type);
        out.writeBytes(intBytes(value.length));
        out.writeBytes(value);
        return this;
    }

    private static byte[] intBytes(int v) {
        return new byte[] {(byte) (v >>> 24), (byte) (v >>> 16), (byte) (v >>> 8), (byte) v};
    }

    static byte[] longBytes(long v) {
        byte[] b = new byte[8];
        for (int i = 7; i >= 0; i--) {
            b[i] = (byte) v;
            v >>>= 8;
        }
        return b;
    }
}
