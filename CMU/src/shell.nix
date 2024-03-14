/**
 * @file "shell.nix"
 * @author Ben Janis
 * @brief Nix shell environment file
 * @date 2024
 *
 * This source file is part of an example system for MITRE's 2024 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2024 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2024 The MITRE Corporation
 */

{ pkgs ? import <nixpkgs> {}
  , fetchzip ? pkgs.fetchzip
  , fetchgit ? pkgs.fetchgit
  , fetchurl ? pkgs.fetchurl
  , unzip ? pkgs.unzip
}:

pkgs.mkShell {
  buildInputs = [
    pkgs.gnumake
    pkgs.python39
    pkgs.gcc-arm-embedded
    pkgs.poetry
    pkgs.cacert
    (pkgs.callPackage custom_nix_pkgs/analog_openocd.nix { })
    pkgs.minicom
  ];

  shellHook = ''
    export PYTHONDONTWRITEBYTECODE=1
  '';

}