{
  description = "secp2565k1-java (Java wrapper for secp256k1)";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-23.11";

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

        # pick our JDK and Maven versions
        jextract = pkgs.jextract;  # Will need update but should be ok for now
        jdk = pkgs.jdk21;          # Should be JDK 22, when/if package is available (EA and then final)
        maven = pkgs.maven;        # Not currently used, but I expect to use Maven, not Gradle

      in {
        # define a devshell
        devShells.default = inputs'.devshell.legacyPackages.mkShell {
          # setup some environment variables
          env = with lib;
            mkMerge [
              [
                # Configure nix to use nixpgks
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
                jextract
                jdk
                maven
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
