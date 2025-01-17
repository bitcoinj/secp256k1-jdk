{
  description = "secp2565k1-jdk (Java API & implementations for secp256k1)";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

    flake-parts = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };

    devshell = {
      url = "github:numtide/devshell";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    gitignore = {
      url = "github:hercules-ci/gitignore.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = inputs @ { flake-parts, devshell , gitignore, ... }:
    flake-parts.lib.mkFlake {inherit inputs;} {
      systems = [ "x86_64-linux" "x86_64-darwin" "aarch64-linux" "aarch64-darwin" ];

      perSystem = { config, self', inputs', pkgs, system, lib, ... }: let
        inherit (pkgs) stdenv;
      in {
        # define default devshell
#        devShells.default = inputs'.devshell.legacyPackages.mkShell {
        devShells.default = pkgs.mkShell {
          # setup some environment variables
#          env = with lib;
#            mkMerge [
#              [
#                # Configure nix to use nixpkgs
#                {
#                  name = "NIX_PATH";
#                  value = "nixpkgs=${toString pkgs.path}";
#                }
#              ]
#              (mkIf stdenv.isLinux [
#                {
#                  name = "JAVA_HOME";
#                  eval = "$DEVSHELL_DIR/lib/openjdk";
#                }
#              ])
#            ];
          inputsFrom = with pkgs ; [ secp256k1 ];
          packages = with pkgs ; [
                jdk23                # JDK 23 will be in $JAVA_HOME (and in javaToolchains)
                # current jextract in nixpkgs is broken, see: https://github.com/NixOS/nixpkgs/issues/354591
                # jextract             # jextract (Nix package) contains a jlinked executable and bundles its own JDK
                (gradle.override {   # Gradle 8.x (Nix package) depends-on and directly uses JDK XX to launch Gradle itself
                    javaToolchains = [ temurin-bin-23 ]; # Put JDK 23 in Gradle's javaToolchain configuration
                })
            ];
        };

        # define flake output packages
        packages = let
          # useful for filtering src trees based on gitignore
          inherit (gitignore.lib) gitignoreSource;

          # common properties across the derivations
          version = "0.0.1";
          src = gitignoreSource ./.;
        in {
           # TBD
        };
      };
    };
}
