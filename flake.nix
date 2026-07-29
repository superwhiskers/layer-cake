{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { nixpkgs, rust-overlay, ... }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems =
        f:
        nixpkgs.lib.genAttrs systems (
          system:
          f {
            inherit system;
            pkgs = import nixpkgs {
              inherit system;
              overlays = [ rust-overlay.overlays.default ];
            };
          }
        );
    in
    {
      devShells = forAllSystems (
        { pkgs, system, ... }:
        let
          rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
          staticPkgs = pkgs.pkgsStatic;

          target =
            {
              x86_64-linux = "x86_64-unknown-linux-musl";
              aarch64-linux = "aarch64-unknown-linux-musl";
            }
            .${system};

          targetUnderscore = pkgs.lib.replaceStrings [ "-" ] [ "_" ] target;
          targetUpper = pkgs.lib.toUpper targetUnderscore;
        in
        {
          default = pkgs.mkShell {
            packages = [
              rustToolchain
              pkgs.cargo-deny
              pkgs.pkg-config
              pkgs.lld
            ];

            CARGO_BUILD_TARGET = target;
            shellHook = ''
              export CARGO_TARGET_${targetUpper}_LINKER="${staticPkgs.stdenv.cc}/bin/${target}-cc"

              # Used by crates whose build.rs invokes the cc crate.
              export CC_${targetUnderscore}="${staticPkgs.stdenv.cc}/bin/${target}-cc"
            '';

            PKG_CONFIG_ALL_STATIC = "1";
            PKG_CONFIG_ALLOW_CROSS = "1";
          };
        }
      );
    };
}
