package org.shalim.testing;

import java.util.Arrays;
import java.util.Objects;

/** Assertions for the dependency-free test runner. */
public final class Check {

    private Check() {
    }

    public static void isTrue(boolean condition, String what) {
        if (!condition) {
            throw new AssertionError(what);
        }
    }

    public static void isFalse(boolean condition, String what) {
        isTrue(!condition, what);
    }

    public static void equal(Object expected, Object actual, String what) {
        if (!Objects.equals(expected, actual)) {
            throw new AssertionError(what + ": expected <" + expected + "> but was <" + actual + ">");
        }
    }

    public static void equalBytes(byte[] expected, byte[] actual, String what) {
        if (!Arrays.equals(expected, actual)) {
            throw new AssertionError(what + ": byte arrays differ");
        }
    }

    public static void notNull(Object value, String what) {
        isTrue(value != null, what + " was null");
    }

    public static void isNull(Object value, String what) {
        isTrue(value == null, what + " was not null");
    }

    public static <T extends Throwable> void throwsA(Class<T> type, Runnable action, String what) {
        try {
            action.run();
        } catch (Throwable t) {
            if (type.isInstance(t)) {
                return;
            }
            throw new AssertionError(what + ": threw " + t + " instead of " + type.getSimpleName(), t);
        }
        throw new AssertionError(what + ": nothing thrown");
    }
}
