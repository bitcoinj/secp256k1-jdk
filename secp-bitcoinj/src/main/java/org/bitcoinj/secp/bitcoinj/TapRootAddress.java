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

import org.bitcoinj.base.Network;
import org.bitcoinj.base.SegwitAddress;
import org.bitcoinj.secp.Secp256k1;
import org.bitcoinj.secp.SecpXOnlyPubKey;

/**
 *
 */
public interface TapRootAddress {
    static SegwitAddress fromXOnlyPubKey(Secp256k1 secp, Network network, SecpXOnlyPubKey xOnlyPubKey) {
        WitnessMaker maker = new WitnessMaker(secp);
        SecpXOnlyPubKey tweakedPubKey = maker.tweakedPubKey(xOnlyPubKey);
        return SegwitAddress.fromProgram(network, 1, tweakedPubKey.toByteArray());
    }
}
