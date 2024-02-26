package org.bitcoinj.secp256k1.api;

/**
 * A single object with a private and public key
 */
public interface P256K1KeyPair extends P256k1PrivKey {
    P256k1PubKey getPublic();
}
