// schnorr.jsh

IO.println("Elliptic Curve Diffie-Hellman Demo")

import module org.bitcoinj.secp

var secp = Secp256k1.get()
var alice = secp.ecKeyPairCreate()
var bob = secp.ecKeyPairCreate()
var secretA = secp.ecdh(bob.publicKey(), alice).get()
var secretB = secp.ecdh(alice.publicKey(), bob).get()
secretA.equals(secretB)
