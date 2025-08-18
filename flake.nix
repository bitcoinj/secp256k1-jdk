{
  description = "secp2565k1-jdk (Java API & implementations for secp256k1)";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

    flake-parts = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };
  };

  outputs = inputs @ { flake-parts, ... }:
    flake-parts.lib.mkFlake {inherit inputs;} {
      systems = [ "x86_64-linux" "x86_64-darwin" "aarch64-linux" "aarch64-darwin" ];

      perSystem = { config, self', inputs', pkgs, system, lib, ... }: let
        inherit (pkgs) stdenv;
        sharedShellHook = ''
            echo "Welcome to secp256k1-jdk!"
        '';
      in {
        # define default devshell, with a richer collection of tools intended for interactive development
        devShells.default = pkgs.mkShell {
          inputsFrom = with pkgs ; [ secp256k1 ];
          packages = with pkgs ; [
                jdk24                      # JDK 24 will be in PATH
                # current jextract in nixpkgs is broken, see: https://github.com/NixOS/nixpkgs/issues/354591
                # jextract                 # jextract (Nix package) contains a jlinked executable and bundles its own JDK
                (gradle.override {         # Gradle 8.x (Nix package) runs using an internally-linked JDK
                    java = jdk24;          # Run Gradle with this JDK
                })
            ];
          shellHook = sharedShellHook;
        };
        # define minimum devshell, with the minimum necessary to do a CI build
        devShells.minimum = pkgs.mkShell {
          inputsFrom = with pkgs ; [ secp256k1 ];
          packages = with pkgs ; [
                (gradle.override {         # Gradle 8.x (Nix package) runs using an internally-linked JDK
                    java = jdk24_headless; # Run Gradle with this JDK
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
