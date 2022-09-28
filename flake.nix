{
  description = "Decrypt your LUKS partition using a FIDO2 compatible authenticator";

  inputs = {
    utils.url = "github:numtide/flake-utils";
    naersk = {
      url = "github:nmattia/naersk";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

outputs = inputs @ { self, nixpkgs, utils, naersk, ... }:
    let
      root = inputs.source or self;
      pname = (builtins.fromTOML (builtins.readFile (root + "/Cargo.toml"))).package.name;
      # toolchains: stable, beta, default(nightly)
      toolchain = pkgs: if inputs ? fenix then inputs.fenix.packages."${pkgs.system}".complete.toolchain 
                  else with pkgs; symlinkJoin { name = "rust-toolchain"; paths = [ rustc cargo ]; };
      forSystem = system:
      let 
        pkgs = nixpkgs.legacyPackages."${system}";
      in
        rec {
          # `nix build`
          packages.${pname} = (self.overlay pkgs pkgs).${pname};

          packages.dockerImage = pkgs.runCommandLocal "docker-${pname}.tar.gz" {} "${apps.streamDockerImage.program} | gzip --fast > $out";

          packages.default = packages.${pname};

          # `nix run`
          apps.${pname} = utils.lib.mkApp {
            drv = packages.${pname};
          };
          
          # `nix run .#streamDockerImage | docker load`
          apps.streamDockerImage = utils.lib.mkApp {
            drv = with pkgs; dockerTools.streamLayeredImage {
              name = pname;
              tag = self.shortRev or "latest";
              config = {
                Entrypoint = apps.default.program;
              };
            };
            exePath = "";
          };
          apps.default = apps.${pname};

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
          devShell = pkgs.mkShell rec {
            RUST_SRC_PATH = "${if inputs ? fenix then "${toolchain pkgs}/lib/rustlib" else pkgs.rustPlatform.rustLibSrc}";
            nativeBuildInputs = with pkgs; [ (toolchain pkgs) cargo-edit rustfmt nixpkgs-fmt ] ++ packages.default.nativeBuildInputs;
            inherit (packages.default) buildInputs LIBCLANG_PATH;
            shellHook = ''
              printf "Rust version:"
              rustc --version
              printf "\nbuild inputs: ${pkgs.lib.concatStringsSep ", " (map (bi: bi.name) (buildInputs ++ nativeBuildInputs))}"
            '';
          };

        };
    in
    (utils.lib.eachDefaultSystem forSystem) // {
      overlays.pinned = final: prev: (self.overlay final (import nixpkgs {
        inherit (final) localSystem;
      })).packages;
      overlay = final: prev:
        let
          naersk-lib = naersk.lib."${final.system}".override {
            rustc = toolchain prev;
            cargo = toolchain prev;
          };
          buildInputs = with prev; [ 
            udev cryptsetup.dev
          ];
          nativeBuildInputs = with prev; [
            pkg-config clang
          ];
        in
        {
          "${pname}" =
            naersk-lib.buildPackage {
              LIBCLANG_PATH = "${final.llvmPackages.libclang.lib}/lib";
              inherit pname root buildInputs nativeBuildInputs;
            };
        };
    };
}
