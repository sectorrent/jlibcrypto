package org.sectorrent.jlibcrypto.kyber;

public class KyberPackedPKI {

    private byte[] packedPublicKey;
    private byte[] packedPrivateKey;

    /**
     *  Default Constructor
     */
    public KyberPackedPKI() {

    }

    /**
     * @return the packedPublicKey
     */
    public byte[] getPackedPublicKey() {
        return packedPublicKey;
    }

    /**
     * @param packedPublicKey the packedPublicKey to set
     */
    public void setPackedPublicKey(byte[] packedPublicKey) {
        this.packedPublicKey = packedPublicKey;
    }

    /**
     * @return the packedPrivateKey
     */
    public byte[] getPackedPrivateKey() {
        return packedPrivateKey;
    }

    /**
     * @param packedPrivateKey the packedPrivateKey to set
     */
    public void setPackedPrivateKey(byte[] packedPrivateKey) {
        this.packedPrivateKey = packedPrivateKey;
    }
}
