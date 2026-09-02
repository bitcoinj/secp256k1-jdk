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
package org.bitcoinj.secp.examples;

import org.bitcoinj.base.internal.Stopwatch;
import org.bitcoinj.secp.SchnorrSignature;
import org.bitcoinj.secp.Secp256k1;
import org.bitcoinj.secp.SecpKeyPair;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.IntStream;

import static java.lang.IO.println;

public class SignMany {
    final int count = 100_000;
    final String msg = "Hello, world!";
    final String tag = "my_fancy_protocol";

    void main() {
        try (Secp256k1 secp = Secp256k1.getById(Secp256k1.ProviderId.LIBSECP256K1_FFM)) {
            println("Creating " + count +  " keyPairs");
            Stopwatch createWatch = Stopwatch.start();
            var keyPairs = IntStream.range(0, count)
                    .mapToObj(i -> secp.ecKeyPairCreate())
                    .toList();
            println("Finished in " + createWatch.stop().toString());

            println("Signing " + count + " messages");
            Stopwatch signWatch = Stopwatch.start();
            byte[] messageHash = secp.taggedSha256(tag, msg);
            var sigs = IntStream.range(0, count)
                    .mapToObj(i -> secp.schnorrSigSign32(messageHash, keyPairs.get(i)))
                    .toList();
            println("Finished in " + signWatch.stop().toString());

            println("Verifying " + count + " signatures");
            Stopwatch verifyWatch = Stopwatch.start();
            int verified = IntStream.range(0, count)
                    .map(i ->  secp.schnorrSigVerify(sigs.get(i), messageHash, keyPairs.get(i).publicKey())
                            .get()
                            .compareTo(false))
                    .sum();
            println("Signatures verified: " + verified);
            println("Finished in " + verifyWatch.stop().toString());
        }
    }
}
