{
  config,
  lib,
  pkgs,
  utils,
  ...
}: {
  options = with lib; let
    globalConfig = config;
    fido2luksDev = {
      config,
      name,
      ...
    }: {
      options = {
        device = mkOption {
          type = types.str;
        };
        credential = mkOption {
          default = null;
          example = "f1d00200d8dc783f7fb1e10ace8da27f8312d72692abfca2f7e4960a73f48e82e1f7571f6ebfcee9fb434f9886ccc8fcc52a6614d8d2";
          type = types.nullOr types.str;
          description = "The FIDO2 credential ID.";
        };

        gracePeriod = mkOption {
          default = 30;
          type = types.int;
          description = "Time in seconds to wait for the FIDO2 key.";
        };

        passwordLess = mkOption {
          default = false;
          type = types.bool;
          description = ''
            Defines whatever to use an empty string as a default salt.

            Enable only when your device is PIN protected, such as <link xlink:href="https://trezor.io/">Trezor</link>.
          '';
        };

        pin = mkOption {
          description = "Should a PIN be requested if required";
          default = true;
          type = types.bool;
        };

        pinPrefixed = mkOption {
          description = "If enabled everything in the salt input up to the first colon ':' will be used as PIN";
          default = false;
          type = types.bool;
        };

        allowDiscards = mkOption {
          description = "Open the LUKS device with discard support for SSDs";
          default = true;
          type = types.bool;
        };

        useToken = mkOption {
          default = true;
          type = types.bool;
          description = ''
            Defines if the LUKS2 container should be opened using a credential embedded in it's header
          '';
        };

        postOpen = mkOption {
          type = types.lines;
          default = "";
        };
        postOpenScript = mkOption {
          readOnly = true;
          default =
            if config.postOpen == ""
            then null
            else (pkgs.writeShellScript "fido2luks-${name}-post" config.postOpen);
        };

        mapper = mkOption {
          readOnly = true;
          default = "/dev/mapper/${name}";
        };
        isUsed = mkOption {
          readOnly = true;
          default =
            lib.attrsToList (
              lib.filterAttrs (
                name: value: value ? device && value.device == config.mapper
              )
              globalConfig.fileSystems
            )
            != [];
        };
        mustUse = mkOption {
          type = types.bool;
          default = true;
        };
        deviceUnit = mkOption {
          type = types.str;
          default = "${utils.escapeSystemdPath config.device}.device";
        };
      };
    };
  in {
    boot.fido2luks = mkOption {
      type = with types; attrsOf (submodule fido2luksDev);
      default = {};
      example = {
        "nixos-crypt" = {
          device = "/dev/nvme0n1p2";
	  # Assuming /dev/nvme0n1p2 contains an LVM2 PV
          postOpen = "vgchange -ay";
        };
      };
    };
  };
  config = {
    assertions =
      [
        {
          assertion = (builtins.compareVersions lib.version "26.05") == 1 || config.boot.initrd.systemd.enable;
          message = "boot.fido2luks requires config.boot.initrd.systemd.enable";
        }
      ]
      ++ (lib.attrValues (
        lib.mapAttrs (_: value: {
          assertion = !value.mustUse || value.isUsed;
          message = "${value.mapper} is unused in fileSystems";
        })
        config.boot.fido2luks
      ));
    warnings = let
      unused = lib.filterAttrs (name: value: !value.isUsed) config.boot.fido2luks;
    in
      map ({value, ...}: "${value.mapper} is not used by any fileSystem") (lib.attrsToList unused);

    # boot.initrd.kernelModules = [ "dm_mod" "dm_crypt" ];
    # USB/HID + dm-crypt support in initrd
    boot.initrd.kernelModules =
      [
        "dm_mod"
        "dm_crypt"
        "xhci_pci"
        "usbhid"
        "hid_generic"
        "uhci_hcd"
        "ehci_pci"
      ]
      ++ config.boot.initrd.luks.cryptoModules;

    # hidraw access rules for FIDO2 tokens
    boot.initrd.services.udev.packages = [pkgs.libfido2];

    boot.initrd.systemd.initrdBin = with pkgs; [
      fido2luks
      cryptsetup
    ];

    boot.initrd.systemd.storePaths = (
      lib.filter (script: script != null) (
        lib.attrValues (lib.mapAttrs (_: cfg: cfg.postOpenScript) config.boot.fido2luks)
      )
    );

    boot.initrd.systemd.services = let
      unit = mapperName: cfg: {
        description = "Unlock ${mapperName} with FIDO2 (fido2luks)";
        wantedBy = ["initrd.target"];
        requiredBy = ["sysroot.mount"];
        before = [
          "sysroot.mount"
          "cryptsetup.target"
          "shutdown.target"
        ];
        conflicts = ["shutdown.target"];
        bindsTo = [cfg.deviceUnit];
        after = [
          cfg.deviceUnit
          "systemd-udevd.service"
          "systemd-modules-load.service"
        ];

        unitConfig.DefaultDependencies = "no";

        environment = {
          FIDO2LUKS_CREDENTIAL_ID = lib.mkIf (cfg.credential != []) cfg.credential;
          # Prompt for the salt/password via the initrd's ask-password agent
          FIDO2LUKS_SALT =
            if cfg.passwordLess
            then "string:"
            else "ask";
          FIDO2LUKS_PASSWORD_HELPER = "${config.boot.initrd.systemd.package}/bin/systemd-ask-password --timeout=0 'FIDO2 password:'";
        };

        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          TimeoutSec = "infinity"; # wait for the user to plug in / touch the key
          ExecStart = "${pkgs.fido2luks}/bin/fido2luks open  ${lib.optionalString cfg.pin "--pin"} ${lib.optionalString cfg.pinPrefixed "--pin-prefixed"} ${lib.optionalString cfg.allowDiscards "--allow-discards"} ${
            lib.optionalString (!cfg.useToken) "--disable-token"
          } ${cfg.device} ${mapperName}";
          ExecStartPost = lib.mkIf (cfg.postOpenScript != null) cfg.postOpenScript;
        };
      };
    in
      lib.mapAttrs' (name: cfg: {
        name = "fido2luks-${name}";
        value = unit name cfg;
      })
      config.boot.fido2luks;
  };
}
