package org.sectorrent.jlibcrypto.sphincs;

public class SphincsPlus {

    public static final int SPX_N = 16; // Hash output length in bytes

    public static final int CRYPTO_SEED_BYTES = 3*SPX_N;

    public SphincsPlus(byte[] b){
    }

    public byte[] sign(){
        return null;
    }

    public void update(byte[] b){
        update(b, 0, b.length);
    }

    public void update(byte[] b, int off, int len){

    }

    public boolean verify(byte[] sigBytes){
        return false;
    }
}
