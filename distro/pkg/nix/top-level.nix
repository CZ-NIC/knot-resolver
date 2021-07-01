with import <nixpkgs> {};

(callPackage ./. {
}).overrideAttrs (attrs: {
  src = ./knot-resolver-{{ version }}.tar.xz;

  # This just breaks in our GitLab CI (not locally and not on hydra.nixos.org)
  installCheckPhase = ''
    meson test --print-errorlogs --no-suite snowflake
  '';
})

