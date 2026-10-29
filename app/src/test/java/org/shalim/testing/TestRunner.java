package org.shalim.testing;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.Comparator;

/**
 * Runs every {@code public static void test*()} method in the listed classes.
 * There is no JUnit because there is no build system yet. When Gradle arrives
 * these become JUnit tests unchanged apart from annotations.
 */
public final class TestRunner {

    private static final String[] CLASSES = {
        "org.shalim.crypto.CryptoPrimitivesTest",
        "org.shalim.crypto.MerkleTest",
        "org.shalim.crypto.ShamirTest",
        "org.shalim.identity.IdentityTest",
        "org.shalim.hub.HubLogTest",
        "org.shalim.hub.CensorDecisionLogTest",
        "org.shalim.hub.NetworkClaimTest",
        "org.shalim.records.SignedRecordsTest",
        "org.shalim.trust.ReplaySamplingTest",
        "org.shalim.transport.ChannelAndWireTest",
        "org.shalim.transport.NetworkClaimsOverTheAirTest",
        "org.shalim.transport.SyncServiceTest",
        "org.shalim.transport.LanTransportTest",
    };

    private TestRunner() {
    }

    public static void main(String[] args) throws Exception {
        int passed = 0;
        int failed = 0;
        for (String name : CLASSES) {
            Class<?> type = Class.forName(name);
            Method[] methods = type.getDeclaredMethods();
            Arrays.sort(methods, Comparator.comparing(Method::getName));
            for (Method method : methods) {
                int mods = method.getModifiers();
                if (!method.getName().startsWith("test") || !Modifier.isStatic(mods)
                        || !Modifier.isPublic(mods) || method.getParameterCount() != 0) {
                    continue;
                }
                String label = type.getSimpleName() + "." + method.getName();
                try {
                    method.invoke(null);
                    passed++;
                    System.out.println("  ok   " + label);
                } catch (InvocationTargetException e) {
                    failed++;
                    System.out.println("  FAIL " + label + " — " + e.getCause());
                }
            }
        }
        System.out.println(passed + " passed, " + failed + " failed");
        if (failed > 0) {
            System.exit(1);
        }
    }
}
