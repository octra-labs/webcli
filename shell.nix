{
  pkgs ? import <nixpkgs> { }
}:
  pkgs.mkShell {
    nativeBuildInputs = with pkgs; [
      gcc
      openssl.dev
      leveldb.dev
      leveldb
      gnumake
      pkg-config
    ];

    NIX_ENFORCE_NO_NATIVE = "0";

    SSL_PREFIX = "${pkgs.openssl.dev}";
    LDB_PREFIX = "${pkgs.leveldb.dev}";

    CPATH = "${pkgs.openssl.dev}/include:${pkgs.leveldb.dev}/include";

    LIBRARY_PATH = "${pkgs.openssl.out}/lib:${pkgs.leveldb.out}/lib";

    CXXFLAGS = "-maes";

  }
