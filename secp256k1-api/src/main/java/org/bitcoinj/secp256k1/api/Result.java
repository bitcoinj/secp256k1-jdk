package org.bitcoinj.secp256k1.api;

/**
 * Functional-style result for secp256k1. Returns either {@link  Ok} or {@link Err}.
 * If result is {@code Ok} the success result is in {@link Ok#result()}, if a failure
 * occurred the error code is in {@link Err#code()}.
 */
public sealed interface Result<T> {
    record Ok<T>(T result) implements Result<T> {}
    record Err<T>(int code) implements Result<T> {}

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
    default T unwrap() {
        return unwrap("Error");
    }
    default T unwrap(String message) {
        if (this instanceof Ok<T> ok) {
            return ok.result();
        } else if (this instanceof Err<T> err) {
           throw new IllegalStateException(message + ": " + err.code());
        } else {
            throw new IllegalStateException("Can't get here");
        }
    }
}
