/*
 * Copyright 2023-2026 secp256k1-jdk Developers.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.bitcoinj.secp;

import java.util.function.Supplier;

/**
 * Functional-style result for secp256k1 -- either {@link Ok} or {@link Err}.
 * If result is {@code Ok} the return value is in {@link Ok#result()}, if a failure
 * occurred the error code is in {@link Err#code()}.
 * <p>
 * The error code (or <q>return value</q> as it is called in the C API) for {@link #OK} or
 * <q>success</q> is {@code 1}. For almost all calls the <i>error code</i> for <q>failure</q>
 * is {@code 0} -- so the behavior is similar to a {@code boolean}. However, the C API uses
 * a (C) `int`, so we return a (Java) `int` for future compatibility.
 * @param <T> type of the return value in a successful result
 */
public /* sealed */ interface SecpResult<T> {
    /**
     * A successful result containing a value of type {@code <T>} in {@link #result()}.
     * @param <T> type of the successful result
     */
    final class Ok<T> implements SecpResult<T> {
        private final T result;

        /**
         * Construct a successful result from a result value
         * @param result result value
         */
        public Ok(T result) {
            this.result = result;
        }

        /**
         * Get the result value
         * @return result value
         */
        public T result() {
            return result;
        }
    }

    /**
     * An error result, with an {@code int} error code in {@link #code()}.
     * @param <T> type of the successful result
     */
    final class Err<T> implements SecpResult<T> {
        private final int code;

        /**
         * Construct an error result from an error code
         * @param code error code
         */
        public Err(int code) {
            this.code = code;
        }

        /**
         * Get the error code
         * @return error code
         */
        public int code() {
            return code;
        }
    }
    /** Error return integer value for success */
    int OK = 1;

    /**
     * Is the result successful ({@link Ok})?
     * @return true if result is {@code instanceof} {@link Ok}
     */
    default boolean isOk() {
        return this instanceof Ok;
    }

    /**
     * Return the error code
     * @return error code -- {@link #OK} for success
     */
    default int errorCode() {
        return (this instanceof Ok) ? OK : ((Err<T>) this).code();
    }

    /**
     * Static constructor for {@link SecpResult.Ok}
     * @param result result value
     * @return successful result
     * @param <T> result type
     */
    static <T> SecpResult<T> ok(T result) {
        return new Ok<>(result);
    }

    /**
     * Static constructor for {@link SecpResult.Err}
     * @param error_code error code
     * @return error result
     * @param <T> expected result type
     */
    static <T> SecpResult<T> err(int error_code) {
        return new Err<>(error_code);
    }

    /**
     * Create a result from an error code and a supplier function. If the error code
     * is {@code 1} ({@link #OK}), the supplier function is invoked to produce a successful result.
     * Otherwise, an error result is returned containing the error code.
     * @param error_code error code
     * @param supplier value supplier
     * @return result
     * @param <T> result value type
     */
    static <T> SecpResult<T> checked(int error_code, Supplier<T> supplier) {
        return (error_code == OK) ? SecpResult.ok(supplier.get()) : SecpResult.err(error_code);
    }

    // TODO: define well-known error codes and messages and map between them
    // TODO: Consider creating an enum (or other type) for results rather than using int.

    /**
     * Get the result value or throw a {@link RuntimeException}
     * @return result value
     */
    default T get() {
        return get("Error");
    }

    /**
     * Get the result value or throw a {@link RuntimeException}
     * @param message error message to include in exception
     * @return result value
     */
    default T get(String message) {
        if (this instanceof Ok) {
            return ((Ok<T>) this).result();
        } else if (this instanceof Err) {
           throw new IllegalStateException(message + ": " + ((Err<T>)this).code());
        } else {
            throw new IllegalStateException("Can't get here");
        }
    }
}
