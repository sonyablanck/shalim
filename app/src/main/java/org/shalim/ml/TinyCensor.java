package org.shalim.ml;

import java.util.List;

/**
 * The reference {@link CensorEngine}: a quantised RoBERTa classifier running
 * on-device via ONNX Runtime Mobile, pinned by artefact hash.
 *
 * <p>Every hub is expected to run this exact artefact — that is what makes
 * screening uniform across the network — but each runs its own copy locally,
 * so there is no service to take offline and no operator to compel.
 *
 * <p>Scope note: this classifies supply and coordination of the harms in
 * {@link Category}, not general offensiveness. A hub discussing naloxone,
 * abortion access, or crossing a border safely must pass. Over-blocking here
 * breaks the app's actual purpose, so ambiguous text becomes
 * {@link Decision#REVIEW} for a human rather than a silent block.
 */
public class TinyCensor implements CensorEngine {

    private ModelPin pin;
    private boolean loaded;
    private boolean verified;

    /** Above this, block outright. Set high; blocking is the last resort. */
    private float blockThreshold;

    /** Above this, route to a moderator. Most positives should land here. */
    private float reviewThreshold;

    /** Bundled term list used when the model is unavailable and policy allows it. */
    private List<String> fallbackBlocklist;

    public TinyCensor() {
        // TODO: pseudo-code
    }

    public TinyCensor(ModelPin pin) {
        // TODO: pseudo-code
    }

    @Override
    public Verdict assess(String text, Surface surface) {
        // PSEUDO-CODE
        //
        // Contract: this never throws and never returns null. Every failure
        // path degrades to REVIEW, because a crash that silently returns
        // "allow" is a safeguarding hole and one that returns "block" makes the
        // hub unusable the moment a model file goes missing.
        //
        // 1. GUARD
        //    IF text blank -> RETURN allow(surface)
        //    IF text longer than maxInputChars -> truncate
        //       // Long input is also an evasion trick: bury the ask in padding
        //       // so it falls outside the window. Truncate from the START too,
        //       // and assess both halves if over budget.
        //
        // 2. NORMALISE FOR EVASION
        //    normalised = lowercase, strip zero-width chars, fold homoglyphs,
        //                 collapse repeated chars, decode leetspeak
        //       // "c0ke", "ᴄoke" and "c-o-k-e" must not read as novel words.
        //       // This is a losing arms race against a determined adversary,
        //       // which is why BLOCK is narrow and REVIEW is the workhorse.
        //
        // 3. INFER
        //    IF NOT loaded OR NOT verified
        //       IF policy allows BLOCKLIST_ONLY -> RETURN assessWithBlocklist(text, surface)
        //       ELSE RETURN review(surface, reason="censor unavailable")
        //    TRY
        //       scores = model.classify(normalised)   // score per Category
        //    CATCH any error
        //       RETURN review(surface, reason="inference failed")
        //
        // 4. APPLY SURFACE THRESHOLDS
        //    // A skill description is a standing public claim; a 150-char
        //    // meeting request is first contact with a stranger and is where
        //    // grooming actually starts. Screen the latter hardest.
        //    (rev, blk) = thresholdsFor(surface)
        //    top = highest-scoring category
        //
        // 5. DECIDE
        //    IF top.score >= blk -> decision = BLOCK
        //    ELSE IF top.score >= rev -> decision = REVIEW
        //    ELSE decision = ALLOW
        //
        // 6. CONTEXT SOFTENING
        //    // The single most important rule in this class. Harm-reduction,
        //    // abortion access, border safety and overdose response all score
        //    // high on a supply classifier while being exactly what Shalim is
        //    // for. Demand explicit supply/coordination signal — offering,
        //    // pricing, quantity, sourcing, transport — before blocking.
        //    IF decision == BLOCK AND NOT hasSupplyOrCoordinationSignal(normalised)
        //       decision = REVIEW
        //
        // 7. BUILD VERDICT
        //    RETURN Verdict(
        //       verdictId, decision, categories above rev, top.score,
        //       modelPinHash = pin.artefactHash, assessedAt = now)
        //       // pin hash stored so this verdict can be invalidated wholesale
        //       // when the artefact changes.
        return null;
    }

    @Override
    public List<Verdict> assessAll(List<String> texts, Surface surface) {
        // TODO: pseudo-code
        return null;
    }

    /**
     * Thresholds per surface. Returns {@code (review, block)}.
     *
     * <p>{@link Surface#MEETING_REQUEST} is the hardest, and it is worth saying
     * why, because 150 characters looks too small to matter. It is not: 150
     * characters is ample for "Purple Haze, 50 an eighth, can drop Thursday" —
     * strain, price, quantity and delivery in under half the budget. The cap
     * stops a conversation, not a transaction. A deal needs one message and the
     * meeting the hub then helpfully schedules on its own premises.
     *
     * <p>So this surface gets the lowest block threshold of any, and it is the
     * one surface where a short message dense with supply signal blocks on its
     * own. Everywhere else the classifier is reading intent from context; here
     * there is barely any context, and terseness is itself the signal — nobody
     * writes 150 characters of pricing to ask for gardening help.
     *
     * <p>The same reasoning bounds it. First contact is also where someone asks
     * "can you help, I think I'm withdrawing" or "do you know anyone who's
     * travelled to Poland for this", and a hub that blocks those has taken the
     * one channel a frightened person had. Context softening in step 6 applies
     * here too, and a block still needs explicit supply or coordination signal.
     * Short and desperate is not short and dealing.
     */
    public float[] thresholdsFor(Surface surface) {
        // PSEUDO-CODE
        //
        // MEETING_REQUEST      -> lowest block threshold of any surface, and the
        //                         review threshold lower still, so most of what
        //                         it catches lands on a moderator rather than
        //                         being refused outright
        // USER_SKILL           -> low. A standing public claim, screened at write
        //                         time, and the person can rephrase it at leisure
        // RESOURCE_DESCRIPTION -> low, same reasoning
        // HUB_QUERY            -> moderate. Questions are exploratory by nature
        //                         and this is the surface where over-blocking
        //                         breaks the product
        // HUB_PROFILE          -> low. Seen by strangers, written once
        // GENERATED_OUTPUT     -> low. The hub's own words in its own voice; it
        //                         should not be the one saying it
        return null;
    }

    /**
     * Whether the text does the things a transaction does: offers, prices,
     * quantifies, sources, or arranges transport or handover. The gate on every
     * block, and the reason a hub can discuss overdose response at all.
     *
     * <p>Weighted hardest on {@link Surface#MEETING_REQUEST}, where price and
     * quantity together in a first message to a stranger have no innocent
     * reading that survives the fact that the sender had to pick this person out
     * of a query result to say it to.
     */
    public boolean hasSupplyOrCoordinationSignal(String normalised, Surface surface) {
        // TODO: pseudo-code
        return false;
    }

    @Override
    public ModelPin pin() {
        // TODO: pseudo-code
        return pin;
    }

    @Override
    public boolean isVerified() {
        // TODO: pseudo-code
        return verified;
    }

    @Override
    public void load() throws ModelUnavailableException {
        // TODO: pseudo-code
    }

    @Override
    public void unload() {
        // TODO: pseudo-code
    }

    @Override
    public boolean isLoaded() {
        // TODO: pseudo-code
        return loaded;
    }

    // --- configuration ----------------------------------------------------

    /** Thresholds are hub-tunable within bounds; they cannot be set to never block. */
    public void setThresholds(float reviewThreshold, float blockThreshold) {
        // TODO: pseudo-code
    }

    /** Degraded path used only where {@code HubPolicy} permits BLOCKLIST_ONLY. */
    public Verdict assessWithBlocklist(String text, Surface surface) {
        // TODO: pseudo-code
        return null;
    }
}
