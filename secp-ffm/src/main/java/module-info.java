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

import org.bitcoinj.secp.Secp256k1;

/**
 * Implementation of {@link Secp256k1} using secp256k1 via Java FFM.
 */
@org.jspecify.annotations.NullMarked
module org.bitcoinj.secp.ffm {
    requires org.bitcoinj.secp;
    requires org.jspecify;

    exports org.bitcoinj.secp.ffm;
    exports org.bitcoinj.secp.ffm.jextract;

    provides Secp256k1.Provider with org.bitcoinj.secp.ffm.ForeignProvider;
}
