package org.sectorrent.jlibcrypto.sphincs.utils;

import org.sectorrent.jlibcrypto.hash.SHA256;

import static org.sectorrent.jlibcrypto.sphincs.SphincsPlusParams.*;

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

    public void seedState(){
        byte[] block = new byte[SPX_SHA256_BLOCK_BYTES];

        for(int i = 0; i < SPX_N; ++i){
            block[i] = pubSeed[i];
        }

        SHA256 hash = new SHA256();
        hash.update(block);
        stateSeeded = hash.getState();
    }
}
