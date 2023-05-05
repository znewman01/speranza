{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    naersk.url = "github:nix-community/naersk";
  };
  outputs = { nixpkgs, fenix, naersk, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        rust = fenix.packages.${system}.fromToolchainFile {
          file = ./rust-toolchain.toml;
          sha256 = "sha256-KXx+ID0y4mg2B3LHp7IyaiMrdexF6octADnAtFIOjrY";
        };
        naersk-lib = naersk.lib.${system}.override {
          rustc = rust;
          cargo = rust;
        };
        python = pkgs.python3.withPackages (ps: with ps; [ seaborn black ]);
      in rec {
        packages.default = let
          cargoPackage =
            (builtins.fromTOML (builtins.readFile ./Cargo.toml)).package;
        in naersk-lib.buildPackage {
          pname = cargoPackage.name;
          inherit (cargoPackage) version;
          root = ./.;
          doCheck = true;
        };
        apps.default = flake-utils.lib.mkApp { drv = packages.default; };
        devShells.default = pkgs.mkShell {
          buildInputs = packages.default.nativeBuildInputs ++ [
            pkgs.nixfmt
            pkgs.rust-analyzer
            pkgs.libiconv
            python
            pkgs.nodePackages.pyright
          ];
        };
      });
}
