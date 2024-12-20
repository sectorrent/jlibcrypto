package org.sectorrent.jlibcrypto.kyber;

import java.security.PrivateKey;

public class KyberPrivateKey implements PrivateKey {

    private byte[] key;

    public KyberPrivateKey(byte[] key){
        this.key = key;
    }

    @Override
    public String getAlgorithm(){
        return "Kyber";
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
