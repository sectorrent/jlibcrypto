package org.sectorrent.jlibcrypto.kyber;

public class KyberUniformRandom {

    private short[] uniformR;
    private int uniformI = 0;

    /**
     * Default Constructor
     */
    public KyberUniformRandom() {

    }

    /**
     * @return the uniformR
     */
    public short[] getUniformR() {
        return uniformR;
    }

    /**
     * @param uniformR the uniformR to set
     */
    public void setUniformR(short[] uniformR) {
        this.uniformR = uniformR;
    }

    /**
     * @return the uniformI
     */
    public int getUniformI() {
        return uniformI;
    }

    /**
     * @param uniformI the uniformI to set
     */
    public void setUniformI(int uniformI) {
        this.uniformI = uniformI;
    }
}
