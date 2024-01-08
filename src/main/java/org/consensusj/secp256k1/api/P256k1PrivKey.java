package org.consensusj.secp256k1.api;

import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;

/**
 *  Verified private secret key
 *  TODO: Override/prevent serialization
 */
public interface P256k1PrivKey extends ECPrivateKey {

    /* package */ static BigInteger toInteger(byte[] bytes) {
        int signum = 0;
        for (byte b : bytes) {
            if (b != 0) {
                signum = 1;
                break;
            }
        }
        return new BigInteger(signum, bytes);
    }

    @Override
    default String getAlgorithm() {
        return "Secp256k1";
    }

    @Override
    default String getFormat() {
        return "Big-endian";
    }

    /**
     * @return 32-bytes, Big endian with no prefix or suffix
     */
    @Override
    byte[] getEncoded();

    @Override
    default BigInteger getS() {
        return toInteger(getEncoded());
    }

    @Override
    default ECParameterSpec getParams() {
        return Secp256k1.EC_PARAMS;
    }

    /**
     * Destroy must be implemented and must not throw (checked) exceptions
     */
    @Override
    void destroy();
}
