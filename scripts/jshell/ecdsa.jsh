// ecdsa.jsh

IO.println("ECDSA Sign/Verify Demo")

import module org.bitcoinj.secp

byte[] sha256(String messageString) throws NoSuchAlgorithmException {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    digest.update(messageString.getBytes());
    return digest.digest();
}

var secp = Secp256k1.get()
var alice = secp.ecKeyPairCreate()
var message = sha256("Hello Stanford!")
var signature = secp.ecdsaSign(message, alice).get()
var isValid = secp.ecdsaVerify(signature, message, alice.publicKey()).get()