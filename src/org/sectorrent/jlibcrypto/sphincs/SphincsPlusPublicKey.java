package org.sectorrent.jlibcrypto.sphincs;

import java.security.PublicKey;

public class SphincsPlusPublicKey implements PublicKey {

    private final byte[] key;

    public SphincsPlusPublicKey(byte[] key){
        this.key = key;
    }

    public byte[] getPublicKeyBytes(){
        return key.clone();
    }

    @Override
    public String getAlgorithm(){
        return "SphincsPlus";
    }

    @Override
    public String getFormat(){
        return "X.509";
    }

    @Override
    public byte[] getEncoded(){
        return key.clone();
    }
}
