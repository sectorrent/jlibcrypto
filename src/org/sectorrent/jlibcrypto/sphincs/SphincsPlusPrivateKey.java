package org.sectorrent.jlibcrypto.sphincs;

import java.security.PrivateKey;

public class SphincsPlusPrivateKey implements PrivateKey {

    private final byte[] key;

    public SphincsPlusPrivateKey(byte[] key){
        this.key = key;
    }

    public byte[] getPrivateKeyBytes(){
        return key.clone();
    }

    @Override
    public String getAlgorithm(){
        return "SphincsPlus";
    }

    @Override
    public String getFormat(){
        return "PKCS#8";
    }

    @Override
    public byte[] getEncoded(){
        return key.clone();
    }
}
