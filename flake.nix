{
  description = "secp2565k1-java (Java wrapper for secp256k1)";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

    flake-parts = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };

    gitignore = {
      url = "github:hercules-ci/gitignore.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    devshell = {
      url = "github:numtide/devshell";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = inputs @ {
    flake-parts,
    devshell,
    gitignore,
    ...
  }:
    flake-parts.lib.mkFlake {inherit inputs;} {
      systems = [
        "x86_64-linux"
        "x86_64-darwin"
        "aarch64-linux"
        "aarch64-darwin"
      ];

      perSystem = {
        config,
        inputs',
        pkgs,
        lib,
        system,
        ...
      }: let
        inherit (pkgs) stdenv;

        # pick our JDK, jextract and Gradle versions
        jdk = pkgs.jdk21;          # Should be JDK 22, see https://github.com/NixOS/nixpkgs/issues/271971
        jextract = pkgs.jextract;  # Last tested with (nixpkgs-unstable, jextract-unstable, Version: 2023-11-27)
        gradle = pkgs.gradle;      # Last tested with Gradle 8.5 (nixpkgs-unstable, gradle, Version: 8.5)
        # secp256k1 library
        secp256k1 = pkgs.secp256k1;

      in {
        # define a devshell
        devShells.default = inputs'.devshell.legacyPackages.mkShell {
          # setup some environment variables
          env = with lib;
            mkMerge [
              [
                # Configure nix to use nixpkgs
                {
                  name = "NIX_PATH";
                  value = "nixpkgs=${toString pkgs.path}";
                }
              ]
              (mkIf stdenv.isLinux [
                {
                  name = "JAVA_HOME";
                  eval = "$DEVSHELL_DIR/lib/openjdk";
                }
              ])
            ];

          # add package dependencies
          packages = with lib;
            mkMerge [
              [
                jdk
                jextract
                gradle
                secp256k1
              ]
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
