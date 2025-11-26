{
  description = "secp2565k1-jdk (Java API & implementations for secp256k1)";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/release-25.11";
  };

  outputs = inputs @ { nixpkgs, ... }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" "x86_64-darwin" ];
      forEachSystem = f: builtins.listToAttrs (map (system: {
        name = system;
        value = f system;
      }) systems);
    in {
      devShells = forEachSystem(system:
        let
        inherit (pkgs) stdenv;
        pkgs = import nixpkgs {
          inherit system;
        };
        jdk = pkgs.jdk25;
        graalvm = pkgs.graalvmPackages.graalvm-ce;
        sharedShellHook = ''
            export LIBSECP_DIR="${pkgs.lib.makeLibraryPath [ pkgs.secp256k1 ]}"
            if [[ "$(uname)" == "Darwin" ]]; then
              export DYLD_LIBRARY_PATH="$LIBSECP_DIR:$DYLD_LIBRARY_PATH"
            else
              export LD_LIBRARY_PATH="$LIBSECP_DIR:$LD_LIBRARY_PATH"
            fi
            # setup GRAALVM_HOME
            export GRAALVM_HOME=${graalvm}
            echo "Welcome to secp256k1-jdk!"
        '';
        in {
        # define default devshell, with a richer collection of tools intended for interactive development
        default = pkgs.mkShell {
          buildInputs = with pkgs ; [ secp256k1 zlib ];
          packages = with pkgs ; [
                jdk                        # This JDK will be in PATH
                # current jextract in nixpkgs is broken, see: https://github.com/NixOS/nixpkgs/issues/354591
                # jextract                 # jextract (Nix package) contains a jlinked executable and bundles its own JDK
                (gradle_9.override {       # Gradle (Nix package) runs using an internally-linked JDK
                    java = jdk;            # Run Gradle with this JDK
                    javaToolchains = [     # Make these JDKs available via the Gradle javaToolchains feature
                      graalvm
                    ];
                })
            ];
          shellHook = sharedShellHook;
        };
        # define minimum devshell, with the minimum necessary to do a CI build
        minimum = pkgs.mkShell {
          buildInputs = with pkgs ; [ secp256k1 zlib ];
          packages = with pkgs ; [
                graalvm                    # This JDK will be in PATH
                (gradle_9.override {       # Gradle (Nix package) runs using an internally-linked JDK
                    java = graalvm;        # Run Gradle with this JDK
                })
            ];
          shellHook = sharedShellHook;
        };
      });
      # define flake output packages
      packages = let
        # common properties across the derivations
        version = "0.0.1";
      in {
        # TBD
      };
  };
}
