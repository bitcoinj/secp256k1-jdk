;; Guix build environment for secp256k1-jdk
(specifications->manifest
  '("openjdk@25:jdk"
     "maven"
     "libsecp256k1"))
