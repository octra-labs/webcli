{
  pkgs ? import <nixpkgs> { }
}:
  pkgs.mkShell {
    nativeBuildInputs = with pkgs; [
      gcc
      gnumake
      pkg-config
    ];

    buildInputs = with pkgs; [
      openssl.dev
      leveldb.dev
      leveldb
    ];

      
    # The Makefile uses -march=native for hardware crypto instructions.
    # This is acceptable for a developer shell on supported CPUs, but is not
    # intended to provide binary-reproducible builds.      
    NIX_ENFORCE_NO_NATIVE = "0";

    SSL_PREFIX = "${pkgs.openssl.dev}";
    LDB_PREFIX = "${pkgs.leveldb.dev}";

    CPATH = "${pkgs.openssl.dev}/include:${pkgs.leveldb.dev}/include";
    LIBRARY_PATH = "${pkgs.openssl.out}/lib:${pkgs.leveldb.out}/lib";

    OCTRA_SKIP_AUTOSETUP=1;
  }
