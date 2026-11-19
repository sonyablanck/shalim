package org.shalim.testing;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import org.shalim.ml.CensorEngine;
import org.shalim.ml.ModelPin;
import org.shalim.ml.ModelUnavailableException;
import org.shalim.ml.Verdict;

/**
 * An honest censor that can be tampered with mid-test while still claiming
 * the honest pin: what a hooked hub looks like from inside.
 */
public final class TamperableCensor implements CensorEngine {

    public enum Mode {
        HONEST,
        /** Lets everything through: under-blocking. */
        PASS_ALL,
        /** Blocks anything containing one of the words: over-blocking. */
        BLOCK_WORDS
    }

    private final CensorEngine honest;
    private volatile Mode mode = Mode.HONEST;
    private volatile List<String> words = List.of();

    public TamperableCensor(CensorEngine honest) {
        this.honest = honest;
    }

    public void tamper(Mode mode, String... words) {
        this.mode = mode;
        this.words = List.of(words);
    }

    @Override
    public Verdict assess(String text, Surface surface) {
        Verdict v = honest.assess(text, surface);
        return switch (mode) {
            case HONEST -> v;
            case PASS_ALL -> new Verdict(Decision.ALLOW, List.of(), 0.02f, v.getModelPinHash(), v.getAssessedAt());
            case BLOCK_WORDS -> {
                String t = text.toLowerCase(Locale.ROOT);
                yield words.stream().anyMatch(t::contains)
                        ? new Verdict(Decision.BLOCK, List.of(Category.CONTROLLED_SUBSTANCE_SUPPLY), 0.96f,
                                v.getModelPinHash(), v.getAssessedAt())
                        : v;
            }
        };
    }

    @Override
    public List<Verdict> assessAll(List<String> texts, Surface surface) {
        List<Verdict> out = new ArrayList<>();
        texts.forEach(t -> out.add(assess(t, surface)));
        return out;
    }

    @Override
    public ModelPin pin() {
        return honest.pin();
    }

    @Override
    public boolean isVerified() {
        return honest.isVerified();
    }

    @Override
    public void load() throws ModelUnavailableException {
        honest.load();
    }

    @Override
    public void unload() {
        honest.unload();
    }

    @Override
    public boolean isLoaded() {
        return honest.isLoaded();
    }
}
