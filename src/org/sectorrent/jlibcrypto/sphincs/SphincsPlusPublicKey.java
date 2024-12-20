package org.sectorrent.jlibcrypto.sphincs;

import java.security.PublicKey;

public class SphincsPlusPublicKey implements PublicKey {

    private final byte[] publicKey;

    public SphincsPlusPublicKey(byte[] publicKey){
        this.publicKey = publicKey;
    }

    public byte[] getPublicKeyBytes(){
        return publicKey.clone();
    }

    @Override
    public String getAlgorithm(){
        return "SPHINCSPLUS";
    }

    @Override
    public String getFormat(){
        return "X.509";
    }

    @Override
    public byte[] getEncoded(){
        return publicKey.clone();
    }
}
