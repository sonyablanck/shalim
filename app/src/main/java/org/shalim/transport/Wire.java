package org.shalim.transport;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

/**
 * The byte encoding for everything sent between devices. Compact, so frames
 * fit LoRa, and strict on the way in, because every byte read here came from
 * someone who may be hostile.
 *
 * <p>Fields are written in a fixed order per message, with no tags.
 * Variable-length fields carry a length prefix: one byte for {@link #small}
 * fields, up to 255 bytes, and four bytes for {@link #bytes}. The reader
 * enforces a maximum on every length, and rejects trailing bytes
 * ({@link Reader#end}). So a malformed or oversized frame fails cleanly as a
 * {@link WireException} and never as an exception from deep in the parser.
 */
public final class Wire {

    private Wire() {
    }

    /** A frame that did not parse. Always caught and the frame dropped. */
    public static final class WireException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public WireException(String message) {
            super(message);
        }
    }

    public static Writer writer() {
        return new Writer();
    }

    public static Reader reader(byte[] frame) {
        return new Reader(frame);
    }

    public static final class Writer {
        private final ByteArrayOutputStream out = new ByteArrayOutputStream();

        public Writer u8(int v) {
            out.write(v & 0xff);
            return this;
        }

        public Writer u32(long v) {
            for (int s = 24; s >= 0; s -= 8) {
                out.write((int) (v >>> s) & 0xff);
            }
            return this;
        }

        public Writer u64(long v) {
            for (int s = 56; s >= 0; s -= 8) {
                out.write((int) (v >>> s) & 0xff);
            }
            return this;
        }

        public Writer bool(boolean v) {
            return u8(v ? 1 : 0);
        }

        /** Exactly {@code n} bytes, no prefix. For keys and hashes of known size. */
        public Writer fixed(byte[] v, int n) {
            if (v == null || v.length != n) {
                throw new IllegalArgumentException("expected " + n + " bytes");
            }
            out.writeBytes(v);
            return this;
        }

        /** Up to 255 bytes with a one-byte length. Null is written as length 255 with no body. */
        public Writer small(byte[] v) {
            if (v == null) {
                return u8(255);
            }
            if (v.length >= 255) {
                throw new IllegalArgumentException("small field too long");
            }
            u8(v.length);
            out.writeBytes(v);
            return this;
        }

        public Writer smallString(String v) {
            return small(v == null ? null : v.getBytes(StandardCharsets.UTF_8));
        }

        /** Up to 2^31 bytes with a four-byte length. Null is length 0xffffffff. */
        public Writer bytes(byte[] v) {
            if (v == null) {
                return u32(0xffffffffL);
            }
            u32(v.length);
            out.writeBytes(v);
            return this;
        }

        public Writer string(String v) {
            return bytes(v == null ? null : v.getBytes(StandardCharsets.UTF_8));
        }

        /** Hex text sent as the bytes it denotes, so hashes cost 32 bytes, not 64. */
        public Writer hex(String v) {
            return small(v == null ? null : org.shalim.crypto.Bytes.fromHex(v));
        }

        public Writer instant(Instant v) {
            if (v == null) {
                return u8(0);
            }
            u8(1);
            u64(v.getEpochSecond());
            return u32(v.getNano());
        }

        public byte[] done() {
            return out.toByteArray();
        }
    }

    public static final class Reader {
        private final byte[] in;
        private int pos;

        private Reader(byte[] frame) {
            if (frame == null) {
                throw new WireException("no frame");
            }
            this.in = frame;
        }

        private void need(int n) {
            if (n < 0 || in.length - pos < n) {
                throw new WireException("frame truncated");
            }
        }

        public int u8() {
            need(1);
            return in[pos++] & 0xff;
        }

        public long u32() {
            need(4);
            long v = 0;
            for (int i = 0; i < 4; i++) {
                v = (v << 8) | (in[pos++] & 0xff);
            }
            return v;
        }

        public long u64() {
            need(8);
            long v = 0;
            for (int i = 0; i < 8; i++) {
                v = (v << 8) | (in[pos++] & 0xff);
            }
            return v;
        }

        public boolean bool() {
            int v = u8();
            if (v > 1) {
                throw new WireException("bad boolean");
            }
            return v == 1;
        }

        public byte[] fixed(int n) {
            need(n);
            byte[] out = new byte[n];
            System.arraycopy(in, pos, out, 0, n);
            pos += n;
            return out;
        }

        public byte[] small() {
            int n = u8();
            return n == 255 ? null : fixed(n);
        }

        public String smallString() {
            byte[] b = small();
            return b == null ? null : new String(b, StandardCharsets.UTF_8);
        }

        public byte[] bytes(int max) {
            long n = u32();
            if (n == 0xffffffffL) {
                return null;
            }
            if (n > max) {
                throw new WireException("field longer than " + max);
            }
            return fixed((int) n);
        }

        public String string(int maxBytes) {
            byte[] b = bytes(maxBytes);
            return b == null ? null : new String(b, StandardCharsets.UTF_8);
        }

        public String hex() {
            byte[] b = small();
            return b == null ? null : org.shalim.crypto.Bytes.hex(b);
        }

        public Instant instant() {
            int present = u8();
            if (present == 0) {
                return null;
            }
            if (present != 1) {
                throw new WireException("bad instant");
            }
            long seconds = u64();
            long nanos = u32();
            if (nanos > 999_999_999L) {
                throw new WireException("bad instant");
            }
            try {
                return Instant.ofEpochSecond(seconds, nanos);
            } catch (java.time.DateTimeException e) {
                throw new WireException("instant out of range");
            }
        }

        public <E extends Enum<E>> E enumValue(Class<E> type) {
            int ordinal = u8();
            E[] values = type.getEnumConstants();
            if (ordinal == 255) {
                return null;
            }
            if (ordinal >= values.length) {
                throw new WireException("unknown " + type.getSimpleName());
            }
            return values[ordinal];
        }

        public int remaining() {
            return in.length - pos;
        }

        /** Every frame must be consumed exactly. */
        public void end() {
            if (pos != in.length) {
                throw new WireException("trailing bytes");
            }
        }
    }

    /** Enum by ordinal, 255 for null. Ordinals are wire format: append new constants, never reorder. */
    public static int ordinal(Enum<?> value) {
        return value == null ? 255 : value.ordinal();
    }
}
