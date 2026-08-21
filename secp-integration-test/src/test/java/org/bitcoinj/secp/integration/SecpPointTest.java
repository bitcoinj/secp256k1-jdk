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
package org.bitcoinj.secp.integration;

import org.bitcoinj.secp.Secp256k1;
import org.bitcoinj.secp.SecpPoint;
import org.bitcoinj.secp.SecpResult;
import org.junit.jupiter.params.ParameterizedClass;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.FieldSource;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.spec.ECPoint;
import java.util.List;

import static java.math.BigInteger.ONE;
import static java.math.BigInteger.ZERO;
import static org.bitcoinj.secp.Secp256k1.P;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/// [SecpPoint] integration tests
@ParameterizedClass
@MethodSource("secpImplementations")
public class SecpPointTest implements SecpTestSupport {
    private final Secp256k1 secp;

    static final List<ECPoint> VALID_ECPOINTS = List.of(
            Secp256k1.G.toECPoint()
            // Need more valid test points
    );
    static final List<ECPoint> INVALID_ECPOINTS = List.of(
            ECPoint.POINT_INFINITY,
            new ECPoint(P.negate(), P.negate()),
            new ECPoint(ONE.negate(), ONE.negate()),
            new ECPoint(ZERO, ZERO),
            new ECPoint(ONE, ONE),
            new ECPoint(ONE, P),
            new ECPoint(P, P)
    );

    /// `@ParameterizedClass` constructor
    /// @param secp injected Secp256k1 implementation to test
    SecpPointTest(Secp256k1 secp) {
        this.secp = secp;
    }

    @FieldSource("VALID_ECPOINTS")
    @ParameterizedTest(name = "p: {0}")
    void testValidImport(ECPoint p) {
        SecpPoint.Uncompressed point = secp.ecPointImport(p).get();
        assertEquals(p.getAffineX(), point.x().toBigInteger());
        assertEquals(p.getAffineY(), point.y().toBigInteger());
    }

    @FieldSource("INVALID_ECPOINTS")
    @ParameterizedTest(name = "p: {0}")
    void testInvalidImport(ECPoint p) {
        IO.println("Testing: "  + p);
        SecpResult<SecpPoint.Uncompressed> result = secp.ecPointImport(p);
        assertNotEquals(SecpResult.OK, result.errorCode());
    }

    @FieldSource("VALID_ECPOINTS")
    @ParameterizedTest(name = "p: {0}")
    void testCompressUncompress(ECPoint p) {
        SecpPoint.Uncompressed uncompressed = secp.ecPointImport(p).get();

        assertEquals(p.getAffineX(), uncompressed.x().toBigInteger());
        assertEquals(p.getAffineY(), uncompressed.y().toBigInteger());

        SecpPoint.Compressed compressed = uncompressed.compress();

        assertEquals(p.getAffineX(), compressed.x().toBigInteger());

        // TODO: SecpPoint.Compressed implementations should support uncompress()
        // SecpPoint.Uncompressed roundTrip = compressed.uncompress();
        // assertEquals(uncompressed, roundTrip);
    }
}
