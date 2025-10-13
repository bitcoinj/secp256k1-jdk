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

import org.bitcoinj.secp.api.SPFieldElement;
import org.bitcoinj.secp.api.SPPoint;

import java.util.Objects;

/**
 *
 */
public
class P256K1PointCompressed implements SPPoint.Compressed {
    private final SPFieldElement x;
    private final boolean isOdd;

    P256K1PointCompressed(SPFieldElement x, SPFieldElement y) {
        this.x = x;
        this.isOdd = y.isOdd();
    }

    @Override
    public SPFieldElement x() {
        return x;
    }

    @Override
    public boolean isOdd() {
        return isOdd;
    }

    @Override
    public Uncompressed uncompress() {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        org.bitcoinj.secp.api.internal.P256K1PointCompressed that = (org.bitcoinj.secp.api.internal.P256K1PointCompressed) o;
        return isOdd == that.isOdd && Objects.equals(x, that.x);
    }

    @Override
    public int hashCode() {
        return Objects.hash(x, isOdd);
    }
}
