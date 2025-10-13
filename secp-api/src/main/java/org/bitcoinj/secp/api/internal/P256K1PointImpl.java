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
package org.bitcoinj.secp.api.internal;

import org.bitcoinj.secp.api.P256K1FieldElement;
import org.bitcoinj.secp.api.P256K1Point;

/**
 * Default implementation of {@link P256K1Point}
 */
public abstract class P256K1PointImpl implements P256K1Point {
    public static P256K1PointUncompressed of(P256K1FieldElement x, P256K1FieldElement y) {
        return new P256K1PointUncompressed(x, y);
    }
}
