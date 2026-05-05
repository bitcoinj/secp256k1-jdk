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
package org.bitcoinj.secp.bitcoinj;

import org.bitcoinj.secp.SecpFieldElement;
import org.bitcoinj.secp.SecpPoint;
import org.bitcoinj.secp.SecpScalar;
import org.bitcoinj.secp.SecpXOnlyPubKey;
import org.bitcoinj.secp.Secp256k1;
import org.bitcoinj.secp.internal.SecpScalarImpl;

import java.nio.charset.StandardCharsets;

/**
 * Experimental class for making P2TR witness programs
 */
public class WitnessMaker {
    static final byte[] TAG_TAP_TWEAK = "TapTweak".getBytes(StandardCharsets.UTF_8);

    private final Secp256k1 secp;

    public WitnessMaker(Secp256k1 secp) {
        this.secp = secp;
    }

    /// P = secp.ecPubKeyFromXOnly(xOnlyPubKey)
    /// The formula from BIP-341:
    /// Q = P + int(hashTapTweak(bytes(P))) * G
    /// returns Q.x()
    /// @param xOnlyPubKey The x-only pubKey
    /// @return tweaked, pubKey as an x-only field element
    public SecpFieldElement tweakedPubKey(SecpXOnlyPubKey xOnlyPubKey) {
        SecpScalar tweak = hashTapTweak(xOnlyPubKey);
        return tweakedPubKey(xOnlyPubKey, tweak);
    }

    /// Return Q.x(), where Q = P + tweak * G
    SecpFieldElement tweakedPubKey(SecpXOnlyPubKey xOnlyPubKey, SecpScalar tweak) {
        SecpPoint.Uncompressed P = secp.ecPubKeyFromXOnly(xOnlyPubKey);
        SecpPoint.Uncompressed tempPoint = secp.ecPubKeyTweakMul(Secp256k1.G, tweak.toBigInteger()).point();
        // tweakedPubKey (aka Q)
        SecpPoint.Uncompressed Q = secp.ecPubKeyCombine(P, tempPoint);
        return Q.x();
    }

    /// int(hashTapTweak(bytes(P)))
    SecpScalar hashTapTweak(SecpXOnlyPubKey xOnlyPubKey) {
        byte[] tweak = secp.taggedSha256(TAG_TAP_TWEAK, xOnlyPubKey.serialize());
        return new SecpScalarImpl(tweak);
    }
}
