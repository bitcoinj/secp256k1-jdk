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
/**
 * API definition module for <a href="https://github.com/bitcoinj/secp256k1-jdk">secp256k1-jdk</a>, a Java library providing
 * <i>Elliptic Curve Cryptography</i> functions using the <a href="https://www.secg.org">SECG</a> curve
 * <a href="https://en.bitcoin.it/wiki/Secp256k1">secp256k1</a>.
 * It provides both ECDSA and Schnorr message signing and verification functions.
 * <p>
 * For more information see the package {@link org.bitcoinj.secp.api} or the main interface
 * {@link org.bitcoinj.secp.api.Secp256k1}.
 */
@org.jspecify.annotations.NullMarked
module org.bitcoinj.secp.api {
    requires org.jspecify;

    exports org.bitcoinj.secp.api;
    exports org.bitcoinj.secp.api.internal to org.bitcoinj.secp.bouncy, org.bitcoinj.secp.ffm, org.bitcoinj.secp.bitcoinj;

    uses org.bitcoinj.secp.api.Secp256k1.Provider;
}
