package org.shalim.query;

import java.util.Optional;

/**
 * A single gate in the ask pipeline. Empty means pass; a result means stop and
 * return it.
 */
public interface QueryGate {
    Optional<QueryResult> check(QueryContext ctx);
}
