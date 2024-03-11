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
package org.bitcoinj.secp256k1.jca;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

/**
 *
 */
public class Test {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        ECFieldFp field = new ECFieldFp(new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16));
        BigInteger a = BigInteger.ZERO;
        BigInteger b = BigInteger.valueOf(7);
        EllipticCurve curve = new EllipticCurve(field, a, b);
        BigInteger Gx = new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
        BigInteger Gy = new BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);
        ECPoint G = new ECPoint(Gx, Gy);
        BigInteger n = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
        int h = 1;
        ECParameterSpec spec = new ECParameterSpec(curve, G, n, h);


        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");

        // This will probably throw on JDK 16+
        // ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256k1");
        // keyGen.initialize(ecSpec);

        // This also fails with JDK 16+ and the "EC" provider, because it doesn't like the "a" value
        // keyGen.initialize(spec);
    }
}
