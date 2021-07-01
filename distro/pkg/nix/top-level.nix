with import <nixpkgs> {};

(callPackage ./. {
}).overrideAttrs (attrs: {
  src = ./knot-resolver-{{ version }}.tar.xz;

  # This just breaks in CI (though not locally).
  installCheckPhase = ''
    meson test --print-errorlogs --no-suite snowflake
  '';
})

