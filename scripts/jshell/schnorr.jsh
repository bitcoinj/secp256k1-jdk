// schnorr.jsh

IO.println("Schnorr Sign/Verify Demo")

import module org.bitcoinj.secp

var secp = Secp256k1.get()
var alice = secp.ecKeyPairCreate()
var taggedMessage = secp.taggedSha256("BitDevs Protocol", "Hello Stanford!")
var schnorrSig = secp.schnorrSigSign32(taggedMessage, alice)
var isValidSchnorr = secp.schnorrSigVerify(schnorrSig, taggedMessage, alice.publicKey()).get()