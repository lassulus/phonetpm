{
  description = "phonetpm: phone as a biometric ssh-agent / age backend";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, rust-overlay }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ rust-overlay.overlays.default ];
        config = {
          allowUnfree = true;
          android_sdk.accept_license = true;
        };
      };
      ndkVersion = "27.2.12479018";
      buildTools = "35.0.0";
      android = pkgs.androidenv.composeAndroidPackages {
        platformVersions = [ "35" ];
        buildToolsVersions = [ buildTools ];
        includeNDK = true;
        ndkVersions = [ ndkVersion ];
        includeEmulator = false;
        includeSystemImages = false;
      };
      sdk = "${android.androidsdk}/libexec/android-sdk";
      rust = pkgs.rust-bin.stable.latest.default.override {
        extensions = [ "rust-src" "rust-analyzer" ];
        targets = [ "aarch64-linux-android" "x86_64-linux-android" ];
      };
      hostSystems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" "x86_64-darwin" ];
      # Host binaries (`phonetpm`, `age-plugin-phone`); the Android app is built in the devShell.
      phonetpm = pkgs: pkgs.rustPlatform.buildRustPackage {
        pname = "phonetpm";
        version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).workspace.package.version;
        src = pkgs.lib.fileset.toSource {
          root = ./.;
          fileset = pkgs.lib.fileset.unions [ ./Cargo.toml ./Cargo.lock ./crates ];
        };
        cargoLock.lockFile = ./Cargo.lock;
        cargoBuildFlags = [ "-p" "phonetpm" ];
        cargoTestFlags = [ "-p" "phonetpm" ];
        meta = {
          description = "phone as a biometric ssh-agent / age backend (host side)";
          license = pkgs.lib.licenses.mit;
          mainProgram = "phonetpm";
          platforms = hostSystems;
        };
      };
    in
    {
      packages = nixpkgs.lib.genAttrs hostSystems (s: {
        default = phonetpm nixpkgs.legacyPackages.${s};
      });

      devShells.${system}.default = pkgs.mkShell {
        packages = [
          rust
          pkgs.cargo-ndk
          pkgs.jdk17
          pkgs.gradle
          android.androidsdk
          pkgs.pkg-config
          pkgs.age
          pkgs.openssh
        ];
        ANDROID_HOME = sdk;
        ANDROID_SDK_ROOT = sdk;
        ANDROID_NDK_HOME = "${sdk}/ndk/${ndkVersion}";
        JAVA_HOME = pkgs.jdk17;
        GRADLE_OPTS = "-Dorg.gradle.project.android.aapt2FromMavenOverride=${sdk}/build-tools/${buildTools}/aapt2";
      };
    };
}
