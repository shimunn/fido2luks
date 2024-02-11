{
  description = "Decrypt your LUKS partition using a FIDO2 compatible authenticator";

  inputs = {
    utils.url = "github:numtide/flake-utils";
    naersk = {
      url = "github:nix-community/naersk";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, utils, naersk }:
    let
      root = ./.;
      pname = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).package.name;
      forPkgs = pkgs:
        let
          naersk-lib = naersk.lib."${pkgs.system}";
          buildInputs = with pkgs; [ cryptsetup cryptsetup.dev ];
          nativeBuildInputs = with pkgs; [
            rustPlatform.bindgenHook
            pkg-config
            clang
          ];
        in
        rec {
          # `nix build`
          packages.${pname} = naersk-lib.buildPackage {
            inherit pname root buildInputs nativeBuildInputs;
          };
          defaultPackage = packages.${pname};

          # `nix run`
          apps.${pname} = utils.lib.mkApp {
            drv = packages.${pname};
          };
          defaultApp = apps.${pname};

          # `nix flake check`
          checks = {
            fmt = with pkgs; runCommandLocal "${pname}-fmt" { buildInputs = [ cargo rustfmt nixpkgs-fmt ]; } ''
              cd ${root}
              cargo fmt -- --check
              nixpkgs-fmt --check *.nix
              touch $out
            '';
          };

          hydraJobs = checks // packages;

          # `nix develop`
          devShell = pkgs.mkShell {
            nativeBuildInputs = with pkgs; [ rustc cargo rustfmt nixpkgs-fmt ] ++ nativeBuildInputs;
            inherit buildInputs;
          };
        };
      forSystem = system: forPkgs nixpkgs.legacyPackages."${system}";
    in
    (utils.lib.eachSystem [ "aarch64-linux" "i686-linux" "x86_64-linux" ] forSystem) // {
      overlay = final: prev: (forPkgs final).packages;
    };

}
