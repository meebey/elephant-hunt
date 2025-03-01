# used by nix-direnv, to setup development environment with VSCode
{ pkgs ? import <nixpkgs> {}}:

# create shell without default dev packages (C compiler, make, etc)
pkgs.mkShellNoCC {
  packages = with pkgs; [
    git
    go
    vscodium
    vscode-extensions.golang.go
    delve # for debugging Go apps
  ];

  #inputsFrom = [ pkgs.hello pkgs.gnutar ];

  shellHook = ''
    # put extra shell commands here
  '';
}

# start "codium" from your shell and happy hacking!