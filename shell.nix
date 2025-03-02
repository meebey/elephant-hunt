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
    vscode-extensions.github.vscode-github-actions
  ];

  # extensions must be activated from within codium. They are automatically
  # recommended for this workspace via .vscode/extensions.json

  #inputsFrom = [ pkgs.hello pkgs.gnutar ];

  shellHook = ''
    # start our codium and open this project workspace, happy hacking!
    ${pkgs.vscodium}/bin/codium $PWD
  '';
}

