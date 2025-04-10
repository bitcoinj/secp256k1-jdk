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

///
/// Implementation of [org.bitcoinj.secp.api] using [libsecp256k1](https://github.com/bitcoin-core/secp256k1)
/// and [Java Foreign Function & Memory API](https://openjdk.org/jeps/454).
///
/// **libsecp256k1** is described as:
/// > High-performance high-assurance C library for digital signatures and other cryptographic primitives on the
/// >secp256k1 elliptic curve.
///
/// **Foreign Function & Memory** (**FFM**), nicknamed *Panama*, allows Java programs to "efficiently invoke foreign functions
/// and safely access foreign memory." **FFM** is a "concise, readable, and pure-Java API" that replaces the earlier
/// [Java Native Interface](https://docs.oracle.com/en/java/javase/21/docs/specs/jni/index.html) (**JNI**.)
///
/// **FFM** was introduced with Java 22 and [org.bitcoinj.secp.ffm] (currently) requires JDK 23 or later -- the 1.0
/// release of [org.bitcoinj.secp.ffm] will require JDK 25 LTS or later. [org.bitcoinj.secp.ffm] is the
/// recommended implementation of [org.bitcoinj.secp.api] for applications running on recent JDK versions and platforms supported
/// by **libsecp256k1**.
///
package org.bitcoinj.secp.ffm;
