/*
 * Copyright 2023-2024 secp256k1-jdk Developers.
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
package org.bitcoinj.secp.eggcc;


import org.bitcoinj.secp.api.P256k1PrivKey;

import java.math.BigInteger;

/**
 *
 */
public class EggPrivKey implements P256k1PrivKey {
    private final BigInteger privkey;

    public EggPrivKey(BigInteger privkey) {
        this.privkey = privkey;
    }

    @Override
    public BigInteger getS() {
        return privkey;
    }

    @Override
    public void destroy() {
        // TODO: TBD!!!
    }

    /**
     * @return 32 bytes, big-endian
     */
    @Override
    public byte[] getEncoded() {
        byte[] minBytes = privkey.toByteArray(); // return minimum, signed bytes
        if (minBytes.length > 33) throw new IllegalStateException("privKey BigInteger value too large");
        // Convert from signed, variable length to unsigned, fixed 8-byte length.
        byte[] result = new byte[32];
        System.arraycopy(minBytes,              // src
                minBytes.length == 33 ? 1 : 0,   // src pos (skip sign byte if present)
                result,                         // dest
                minBytes.length == 33 ? 0 : 32 - minBytes.length,  // dest position
                minBytes.length == 33 ? 32 : minBytes.length);
        return result;
    }
}
