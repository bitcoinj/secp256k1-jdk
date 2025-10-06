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
package org.bitcoinj.secp.graalvmffm;

import org.graalvm.nativeimage.hosted.Feature;
import org.graalvm.nativeimage.hosted.RuntimeForeignAccess;

import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;

import static java.lang.foreign.ValueLayout.*;

/**
 * Register secp methods for GraalVM Foreign Access. All code within feature classes is executed during native image generation,
 * and never at runtime.
 */
public class ForeignRegistrationFeature implements Feature {

    /**
     * Required no-argument constructor.
     */
    public ForeignRegistrationFeature() {};

    /**
     * Handler for initializations at startup time. It allows customization of the static analysis setup.
     * @param access The supported operations that the feature can perform at this time
     */
    public void duringSetup(Feature.DuringSetupAccess access) {
        RuntimeForeignAccess.registerForDowncall(FunctionDescriptor.ofVoid());
        RuntimeForeignAccess.registerForDowncall(FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_INT));
        RuntimeForeignAccess.registerForDowncall(FunctionDescriptor.of(JAVA_LONG, JAVA_INT));
        RuntimeForeignAccess.registerForDowncall(FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_INT, JAVA_INT));
        RuntimeForeignAccess.registerForDowncall(FunctionDescriptor.of(JAVA_INT, JAVA_LONG, JAVA_LONG, JAVA_LONG));
        RuntimeForeignAccess.registerForDowncall(FunctionDescriptor.of(JAVA_INT, JAVA_LONG, JAVA_LONG, JAVA_LONG, JAVA_LONG, JAVA_LONG));
        RuntimeForeignAccess.registerForDowncall(FunctionDescriptor.of(JAVA_INT, JAVA_LONG, JAVA_LONG, JAVA_LONG, JAVA_LONG, JAVA_LONG, JAVA_LONG));
        RuntimeForeignAccess.registerForDowncall(FunctionDescriptor.of(JAVA_INT, JAVA_LONG, JAVA_LONG, JAVA_LONG, JAVA_LONG, JAVA_INT));
        RuntimeForeignAccess.registerForDowncall(FunctionDescriptor.of(JAVA_INT, JAVA_LONG, JAVA_LONG));
        RuntimeForeignAccess.registerForDowncall(FunctionDescriptor.ofVoid(JAVA_LONG, JAVA_LONG));
        RuntimeForeignAccess.registerForDowncall(FunctionDescriptor.ofVoid(JAVA_LONG));
        RuntimeForeignAccess.registerForDowncall(FunctionDescriptor.ofVoid(JAVA_INT, JAVA_INT));
        RuntimeForeignAccess.registerForDowncall(FunctionDescriptor.of(ADDRESS, JAVA_INT, JAVA_INT), Linker.Option.firstVariadicArg(1));
        RuntimeForeignAccess.registerForDowncall(FunctionDescriptor.ofVoid(JAVA_INT), Linker.Option.captureCallState("errno"));
    }
}
