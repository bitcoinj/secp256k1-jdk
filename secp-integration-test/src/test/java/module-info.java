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
import org.bitcoinj.secp.Secp256k1;

/// Integration test module
@org.jspecify.annotations.NullMarked
module org.bitcoinj.secp.integrationtest.test {
    requires org.bitcoinj.secp;
    requires org.bitcoinj.secp.bouncy;
    requires org.bitcoinj.secp.ffm;
    requires org.jspecify;
    requires org.junit.jupiter.api;
    requires com.opencsv;
    requires org.junit.jupiter.params;

    exports org.bitcoinj.secp.integration;
    opens org.bitcoinj.secp.integration;

    exports org.bitcoinj.secp.integration.internal;
    opens org.bitcoinj.secp.integration.internal;

    uses Secp256k1.Provider;
}
