package org.sectorrent.jlibcrypto.kyber.utils;

public class UnpackedPublicKey {

    private short[][] publicKeyPolyvec;
    private byte[] seed;

    /**
     * Default Constructor
     */
    public UnpackedPublicKey() {

    }

    /**
     * @return the publicKeyPolyvec
     */
    public short[][] getPublicKeyPolyvec() {
        return publicKeyPolyvec;
    }

    /**
     * @param publicKeyPolyvec the publicKeyPolyvec to set
     */
    protected void setPublicKeyPolyvec(short[][] publicKeyPolyvec) {
        this.publicKeyPolyvec = publicKeyPolyvec;
    }

    /**
     * @return the seed
     */
    public byte[] getSeed() {
        return seed;
    }

    /**
     * @param seed the seed to set
     */
    protected void setSeed(byte[] seed) {
        this.seed = seed;
    }
}
