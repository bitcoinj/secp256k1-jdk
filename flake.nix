{
  description = "secp2565k1-jdk (Java API & implementations for secp256k1)";

  inputs = {
    nixpkgs.url = "github:nixpkgs-jdk-ea/nixpkgs/jdk-ea-25";

    flake-parts = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };
  };

  outputs = inputs @ { nixpkgs, flake-parts, ... }:
    flake-parts.lib.mkFlake {inherit inputs;} {
      systems = [ "x86_64-linux" "x86_64-darwin" "aarch64-linux" "aarch64-darwin" ];

      perSystem = { config, self', inputs', pkgs, system, lib, ... }: let
        inherit (pkgs) stdenv;
        allowedUnfree = [ "graalvm-oracle" ]; # list of allowed unfree packages
        pkgs = import nixpkgs {
          inherit system;
          config.allowUnfreePredicate = pkg:
            builtins.elem (pkgs.lib.getName pkg) allowedUnfree;
        };
        graalvm = pkgs.graalvmPackages.graalvm-oracle_25-ea;
        sharedShellHook = ''
            if [[ "$(uname)" == "Darwin" ]]; then
              export DYLD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath [ pkgs.secp256k1 ]}:$DYLD_LIBRARY_PATH"
            else
              export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath [ pkgs.secp256k1 ]}:$LD_LIBRARY_PATH"
            fi
            # setup GRAALVM_HOME
            export GRAALVM_HOME=${graalvm}
            echo "Welcome to secp256k1-jdk!"
        '';
      in {
        # define default devshell, with a richer collection of tools intended for interactive development
        devShells.default = pkgs.mkShell {
          inputsFrom = with pkgs ; [ secp256k1 ];
          packages = with pkgs ; [
                graalvm                    # This JDK will be in PATH
                # current jextract in nixpkgs is broken, see: https://github.com/NixOS/nixpkgs/issues/354591
                # jextract                 # jextract (Nix package) contains a jlinked executable and bundles its own JDK
                (gradle_9.override {       # Gradle (Nix package) runs using an internally-linked JDK
                    java = graalvm;        # Run Gradle with this JDK
                })
            ];
          shellHook = sharedShellHook;
        };
        # define minimum devshell, with the minimum necessary to do a CI build
        devShells.minimum = pkgs.mkShell {
          inputsFrom = with pkgs ; [ secp256k1 ];
          packages = with pkgs ; [
                graalvm                    # This JDK will be in PATH
                (gradle_9.override {       # Gradle (Nix package) runs using an internally-linked JDK
                    java = graalvm;        # Run Gradle with this JDK
                })
            ];
          shellHook = sharedShellHook;
        };

        # define flake output packages
        packages = let
          # common properties across the derivations
          version = "0.0.1";
        in {
           # TBD
        };
      };
    };
}
