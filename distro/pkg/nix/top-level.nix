with import <nixpkgs> {};

(callPackage ./. {
}).overrideAttrs (attrs: {
  src = ./knot-resolver-{{ version }}.tar.xz;
})

