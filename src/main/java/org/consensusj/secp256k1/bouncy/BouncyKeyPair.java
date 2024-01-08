package org.consensusj.secp256k1.bouncy;

import org.consensusj.secp256k1.api.P256K1KeyPair;

/**
 *
 */
public class BouncyKeyPair implements P256K1KeyPair {

    private final BouncyPrivKey privKey;
    private final BouncyPubKey pubKey;

    public BouncyKeyPair(BouncyPrivKey privKey, BouncyPubKey pubKey) {
        this.privKey = privKey;
        this.pubKey = pubKey;

    }
    @Override
    public BouncyPubKey getPublic() {
        return pubKey;
    }
    
    @Override
    public byte[] getEncoded() {
        return privKey.getEncoded();
    }

    @Override
    public void destroy() {
    }
}
