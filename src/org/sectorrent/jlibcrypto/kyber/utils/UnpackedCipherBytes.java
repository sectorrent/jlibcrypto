package org.sectorrent.jlibcrypto.kyber.utils;

public class UnpackedCipherBytes {

    private short[][] bp;
    private short[] v;

    /**
     * Default Constructor
     */
    public UnpackedCipherBytes() {

    }

    /**
     * @return the bp
     */
    public short[][] getBp() {
        return bp;
    }

    /**
     * @param bp the bp to set
     */
    protected void setBp(short[][] bp) {
        this.bp = bp;
    }

    /**
     * @return the v
     */
    public short[] getV() {
        return v;
    }

    /**
     * @param v the v to set
     */
    protected void setV(short[] v) {
        this.v = v;
    }
}
