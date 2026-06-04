// providers.jsh

IO.println("Providers Demo")

import module org.bitcoinj.secp

var providers = Secp256k1.all().toList()
var ids = Secp256k1.all().map(Secp256k1.Provider::id).toList()

var libsecp = Secp256k1.get()
var bouncy = Secp256k1.getById("bouncy-castle")

