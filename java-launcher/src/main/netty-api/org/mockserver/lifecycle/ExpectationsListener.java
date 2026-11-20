package org.mockserver.lifecycle;

import org.mockserver.mock.Expectation;

import java.util.List;

/**
 * MockServer 9.2.0's {@code org.mockserver.lifecycle.ExpectationsListener} (in {@code mockserver-netty}), so code
 * that names it compiles; the process-backed server cannot call it, and {@code registerListener} throws.
 */
public interface ExpectationsListener {

    void updated(List<Expectation> expectations);

}
