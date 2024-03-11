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
package org.bitcoinj.secp256k1.bouncy;

import org.bitcoinj.secp256k1.api.P256k1PrivKey;
import org.bouncycastle.math.ec.custom.sec.SecP256K1FieldElement;

import java.math.BigInteger;
import java.util.Arrays;

/**
 *
 */
// TODO: Remove API dependency on o.bouncycastle.m.e.c.s.SecP256K1FieldElement
public class BouncyPrivKey extends SecP256K1FieldElement implements P256k1PrivKey {

    private boolean isDestroyed = false;

    public BouncyPrivKey(BigInteger val) {
        super(val);
    }
    @Override
    public byte[] getEncoded() {
        if (isDestroyed) throw new IllegalStateException("is destroyed");
        return super.getEncoded();
    }

    @Override
    public void destroy() {
        // TODO: Make sure the zeroing is not optimized out by the compiler or JIT
        Arrays.fill(x, (byte) 0x00);
        isDestroyed = true;
    }

    @Override
    public boolean isDestroyed() {
        return isDestroyed;
    }
}
