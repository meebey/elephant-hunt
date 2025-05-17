# build with:
# nix-build --expr 'let pkgs = import <nixpkgs> { }; in pkgs.callPackage ./package.nix { gitReference = "BRANCH_REF"; }'
{ lib, buildGoModule, fetchFromGitHub, ... }:

buildGoModule rec {
  pname = "elephant-hunt";
  version = "unstable-2025-05-17";
  #gitReference = "main";
  gitReference = "0e58ef791383fb23852dea2c9d23c1d664413686";

  src = fetchFromGitHub {
    owner = "meebey";
    repo = "elephant-hunt";
    rev = gitReference;
    name = "${pname}-source-${version}-${gitReference}";
    # retrieved with: nix --extra-experimental-features "nix-command flakes" flake prefetch github:meebey/elephant-hunt/$gitRef
    hash = "sha256-xW4ztAXZ+1EUkb+0muDE2rOpYOAHFqLvWHEj+U83CLA=";
  };

  #vendorHash = lib.fakeHash;
  vendorHash = "sha256-4nxLAMHEAiBRQrGdSUBEvVyOe4gUMO5CmgzYREqE0Bs=";

  meta = with lib; {
    homepage = "https://github.com/meebey/elephant-hunt";
    description = "LLM-powered web honeypot";
    license = licenses.gpl3;
  };
}