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
package org.bitcoinj.secp;

import org.bitcoinj.secp.internal.SecpFieldElementImpl;
import org.bitcoinj.secp.internal.SecpXOnlyPubKeyImpl;

import java.math.BigInteger;

/**
 * An x-only public key from a point on the secp256k1 curve
 */
public interface SecpXOnlyPubKey {
    /**
     *  Get X as a {@link BigInteger}
     * @return X as a {@link BigInteger}
     */
    BigInteger getX();

    /**
     * Serialize as a 32-byte, Big-endian byte array
     * @return Big-endian, 32 bytes
     */
    byte[] serialize();

    /**
     * Parses a serialized x-only pubkey and returns an instance of the default implementation
     * <p>
     * This method is <b>deprecated</b> because it <b>does not validate</b> they x-only pubkey.
     * @param serialized byte string in x-only pubkey serialization format
     * @return an instance of the default implementation
     * @deprecated Use {@link Secp256k1#xOnlyPubKeyParse(byte[])} instead
     */
    @Deprecated(forRemoval = true)
    static SecpResult<SecpXOnlyPubKey> parse(byte[] serialized) {
        return !SecpFieldElementImpl.isInRange(serialized)
                ? SecpResult.err(-1)
                : SecpResult.ok(new SecpXOnlyPubKeyImpl(SecpFieldElement.of(serialized)));
    }
}
