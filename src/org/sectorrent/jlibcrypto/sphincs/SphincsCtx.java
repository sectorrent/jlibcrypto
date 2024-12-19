package org.sectorrent.jlibcrypto.sphincs;

import static org.sectorrent.jlibcrypto.sphincs.Sphincs.SPX_N;

public class SphincsCtx {

    private byte[] pubSeed = new byte[SPX_N];
    private byte[] skSeed = new byte[SPX_N];
    private byte[] stateSeeded;

    public SphincsCtx(){
    }

    public void setPubSeed(byte[] pubSeed){
        this.pubSeed = pubSeed;
    }

    public byte[] getPubSeed(){
        return pubSeed;
    }

    public void setSkSeed(byte[] skSeed){
        this.skSeed = skSeed;
    }

    public byte[] getSkSeed(){
        return skSeed;
    }

    public void setStateSeeded(byte[] stateSeeded){
        this.stateSeeded = stateSeeded;
    }

    public byte[] getStateSeeded(){
        return stateSeeded;
    }
}
