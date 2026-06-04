// ecc-basics.jsh

IO.println("ECC Basics Demo")

import module org.bitcoinj.secp

var P = Secp256k1.P.toString(16)
var G = Secp256k1.G

var secp = Secp256k1.get()
var priv = secp.ecPrivKeyCreate()
var pub = secp.ecPubKeyCreate(priv)
