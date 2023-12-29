package org.consensusj.secp256k1.api;

import java.util.Optional;

/**
 *
 */
public interface Secp256k1 extends AutoCloseable {
    P256k1PrivKey ecPrivKeyCreate();

    P256k1PubKey ecPubKeyCreate(P256k1PrivKey seckey);

    Optional<Object> ecKeyPairCreate();

    CompressedPubKeyData ecPubKeySerialize(P256k1PubKey pubKey, int flags);

    Optional<P256k1PubKey> ecPubKeyParse(CompressedPubKeyData inputData);

    Optional<SignatureData> ecdsaSign(byte[] msg_hash_data, P256k1PrivKey seckey);

    Optional<CompressedSignatureData> ecdsaSignatureSerializeCompact(SignatureData sig);

    Optional<SignatureData> ecdsaSignatureParseCompact(CompressedSignatureData serialized_signature);

    Optional<Boolean> ecdsaVerify(SignatureData sig, byte[] msg_hash_data, P256k1PubKey pubKey);
}
