package org.sectorrent.jlibcrypto.sphincs;

import java.security.PrivateKey;

public class SphincsPlusPrivateKey implements PrivateKey {

    private final byte[] privateKey;

    public SphincsPlusPrivateKey(byte[] privateKey){
        this.privateKey = privateKey;
    }

    public byte[] getPrivateKeyBytes(){
        return privateKey.clone();
    }

    @Override
    public String getAlgorithm(){
        return "SPHINCSPLUS";
    }

    @Override
    public String getFormat(){
        return "PKCS#8";
    }

    @Override
    public byte[] getEncoded(){
        return privateKey.clone();
    }
}
