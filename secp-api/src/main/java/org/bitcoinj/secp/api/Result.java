/*
 * Copyright 2023-2025 secp256k1-jdk Developers.
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
package org.bitcoinj.secp.api;

/**
 * Functional-style result for secp256k1. Returns either {@link  Ok} or {@link Err}.
 * If result is {@code Ok} the success result is in {@link Ok#result()}, if a failure
 * occurred the error code is in {@link Err#code()}.
 */
public /* sealed */ interface Result<T> {
    final class Ok<T> implements Result<T> {
        private final T result;

        public Ok(T result) {
            this.result = result;
        }

        public T result() {
            return result;
        }
    }
    final class Err<T> implements Result<T> {
        private final int code;

        public Err(int code) {
            this.code = code;
        }

        public int code() {
            return code;
        }
    }

    static <T> Result<T> ok(T result) {
        return new Ok<>(result);
    }

    static <T> Result<T> err(int error_code) {
        return new Err<>(error_code);
    }

    /**
     * Return a value if error_code is equal to one (no error).
     */
    static <T> Result<T> checked(int error_code, T result) {
        return (error_code == 1) ? Result.ok(result) : Result.err(error_code);
    }

    // TODO: define well-known error codes and messages and map between them
    // TODO: Consider creating an enum (or other type) for results rather than using int.
    default T get() {
        return get("Error");
    }
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
