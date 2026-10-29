package org.shalim.transport;

/**
 * First byte of every frame. Values are wire format: never renumber.
 *
 * <p>Outer types travel in the clear and are each safe to show an observer:
 * a handshake, a claim query, a rolling beacon, a public card. Everything
 * else travels inside {@link #SEALED}, encrypted to one authenticated session.
 */
public final class MessageType {

    private MessageType() {
    }

    // --- outer, in the clear ---------------------------------------------
    public static final int HANDSHAKE_1 = 0x01;
    public static final int HANDSHAKE_2 = 0x02;
    public static final int HANDSHAKE_3 = 0x03;
    public static final int SEALED = 0x04;
    public static final int CLAIM_QUERY = 0x10;
    public static final int CLAIM_ANSWER = 0x11;
    public static final int BEACON = 0x20;
    public static final int CARD = 0x21;

    // --- inner, inside SEALED --------------------------------------------
    public static final int HELLO = 0x40;
    public static final int LOG_ENTRIES = 0x41;
    public static final int DONE = 0x42;
    public static final int DELIVERY = 0x43;
}
