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
        "x86_64-darwin"
        "aarch64-darwin"
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
        { pkgs, ... }:
        let
          rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
          cross = pkgs.pkgsCross.gnu32;
        in
        {
          default = pkgs.mkShell {
            packages = [
              rustToolchain
              pkgs.cargo-deny
              pkgs.pkg-config
              pkgs.dbus.lib
              pkgs.dbus.dev

              # used for testing 32-bit compatibility
              cross.stdenv.cc
            ];

            shellHook = ''
              export CARGO_TARGET_I686_UNKNOWN_LINUX_GNU_LINKER=${cross.stdenv.cc}/bin/${cross.stdenv.cc.targetPrefix}cc
            '';
          };
        }
      );
      packages = forAllSystems (
        { pkgs, ... }: {
          linuxHeaders = pkgs.linuxHeaders.overrideAttrs (
            final: _: {
              version = "7.1.2";
              src = pkgs.fetchurl {
                url = "mirror://kernel/linux/kernel/v${pkgs.lib.versions.major final.version}.x/linux-${final.version}.tar.xz";
                hash = "sha256-NxmMk3J74kfJ+1MJu4bNXklsYeUyLNjE7KlHa7C1iD8=";
              };
              patches = [ ];
            }
          );
        }
      );
    };
}
