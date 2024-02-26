package org.bitcoinj.secp256k1.eggcc;

import org.bouncycastle.math.ec.custom.sec.SecP256K1FieldElement;

import java.math.BigInteger;
import java.nio.ByteBuffer;

/**
 *
 */
public class Element extends SecP256K1FieldElement {

    /**
     * @param val Unsigned big-endian Byte Array
     */
    public Element(byte[] val) {
        super(byteArrayToIntArray(val));
    }

    public Element(BigInteger val) {
        super(val);
    }

    private static int[] byteArrayToIntArray(byte[] val) {
        if (val.length % 4 != 0) throw new IllegalArgumentException("val must be multiple of 4 bytes long");
        int len = val.length / 4;
        int[] result = new int[len];
        ByteBuffer buf = ByteBuffer.wrap(val);
        for (int i = 0 ; i < len ; i++) {
            result[i] = buf.getInt();
        }
        return result;
    }

    /**
     *
     * @param val Unsigned big-endian Byte Array
     * @return If val is zero, signum of 0, otherwise 1
     */
    private static int calcSignum(byte[] val) {
        for (byte b : val) {
            if (b != 0) {
                return 1;
            }
        }
        return 0;
    }
}
