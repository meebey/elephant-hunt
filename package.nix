{ lib, buildGoModule, fetchFromGitHub, ... }:

buildGoModule rec {
  pname = "elephant-hunt";
  version = "unstable-2025-03-01";
  #gitReference = "main";
  gitReference = "a6949a3245ee2e7c4b12b4b5a49b78ddbca668e8";

  src = fetchFromGitHub {
    owner = "meebey";
    repo = "elephant-hunt";
    rev = gitReference;
    name = "${pname}-source-${version}-${gitReference}";
    # retrieved with: nix --extra-experimental-features "nix-command flakes" flake prefetch github:0x4D31/galah/$gitRef
    hash = "sha256-i/XEKinHm1/HWstj/gQmYqpsexBe1Q4j6ou+LMeJxuU=";
  };

  #vendorHash = lib.fakeHash;
  vendorHash = "sha256-kqzXR7mslKPKr7Ky56ovh5G4pLTCNXEJBFq/MCSPg8g=";

  meta = with lib; {
    homepage = "https://github.com/meebey/elephant-hunt";
    description = "LLM-powered web honeypot";
    license = licenses.gpl3;
  };
}