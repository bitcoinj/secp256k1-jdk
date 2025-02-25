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
        devShells.default = pkgs.mkShell {
          inputsFrom = with pkgs ; [ secp256k1 ];
          packages = with pkgs ; [
                jdk23                      # JDK 23 will be in PATH
                # current jextract in nixpkgs is broken, see: https://github.com/NixOS/nixpkgs/issues/354591
                # jextract                 # jextract (Nix package) contains a jlinked executable and bundles its own JDK
                (gradle.override {         # Gradle 8.x (Nix package) runs using an internally-linked JDK
                    java = jdk23;          # Run Gradle with this JDK
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
