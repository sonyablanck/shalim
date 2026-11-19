package org.shalim.ml.stub;

import java.time.Clock;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.shalim.crypto.Canonical;
import org.shalim.ml.CensorEngine;
import org.shalim.ml.ModelPin;
import org.shalim.ml.ModelUnavailableException;
import org.shalim.ml.Verdict;

/**
 * A stand-in for TinyCensor that returns <em>fixed</em> verdicts: text
 * containing a phrase from its table gets that phrase's decision and
 * category; anything else is ALLOW.
 *
 * <p><strong>Not a safety control.</strong> It exists so that everything
 * around the censor (the decision log, receipts, replay, held queues, meeting
 * screening) can be built and tested with outputs known in advance, as the
 * build order requires before real models arrive in stage 6. It ships with an
 * empty table, deliberately: a phrase list written here would be read as a
 * blocklist by whoever found it, and it would be a bad one.
 *
 * <p>Its pin hashes its own table, so two hubs with different tables have
 * different pins and diverge visibly in sync, as two different models would.
 */
public final class FixedCensor implements CensorEngine {

    /** One row of the table. */
    public record Rule(Decision decision, Category category, float confidence) {
    }

    private final Map<String, Rule> table;
    private final Clock clock;
    private final ModelPin pin;
    private boolean loaded;
    private boolean verified = true;

    public FixedCensor(Map<String, Rule> table, Clock clock) {
        this.table = new LinkedHashMap<>();
        table.forEach((k, v) -> this.table.put(k.toLowerCase(Locale.ROOT), v));
        this.clock = clock;
        List<String> rows = new ArrayList<>();
        this.table.forEach((k, v) -> rows.add(k + "=" + v.decision() + "/" + v.category() + "/" + v.confidence()));
        this.pin = new ModelPin(ModelPin.Purpose.CENSOR, "fixed-censor-stub", "0",
                Canonical.of("shalim.stub.censor.v1").strings(rows).digestHex(), "jvm", "none");
    }

    public FixedCensor(Map<String, Rule> table) {
        this(table, Clock.systemUTC());
    }

    /** An ALLOW-everything stub. */
    public FixedCensor() {
        this(Map.of());
    }

    /** Simulates a tampered artefact, for exercising the integrity path. */
    public void simulateTampering() {
        this.verified = false;
    }

    @Override
    public Verdict assess(String text, Surface surface) {
        if (!loaded) {
            // Must not throw; degrade to REVIEW instead.
            return new Verdict(Decision.REVIEW, List.of(), 0f, pin.getArtefactHash(), clock.instant());
        }
        String t = text == null ? "" : text.toLowerCase(Locale.ROOT);
        Decision worst = Decision.ALLOW;
        List<Category> categories = new ArrayList<>();
        float confidence = 0.01f;
        for (Map.Entry<String, Rule> e : table.entrySet()) {
            if (!e.getKey().isEmpty() && t.contains(e.getKey())) {
                Rule r = e.getValue();
                if (r.decision().compareTo(worst) > 0) {
                    worst = r.decision();
                }
                if (r.category() != null && !categories.contains(r.category())) {
                    categories.add(r.category());
                }
                confidence = Math.max(confidence, r.confidence());
            }
        }
        return new Verdict(worst, categories, confidence, pin.getArtefactHash(), clock.instant());
    }

    @Override
    public List<Verdict> assessAll(List<String> texts, Surface surface) {
        List<Verdict> out = new ArrayList<>();
        for (String t : texts) {
            out.add(assess(t, surface));
        }
        return out;
    }

    @Override
    public ModelPin pin() {
        return pin;
    }

    @Override
    public boolean isVerified() {
        return loaded && verified;
    }

    @Override
    public void load() throws ModelUnavailableException {
        loaded = true;
    }

    @Override
    public void unload() {
        loaded = false;
    }

    @Override
    public boolean isLoaded() {
        return loaded;
    }
}
