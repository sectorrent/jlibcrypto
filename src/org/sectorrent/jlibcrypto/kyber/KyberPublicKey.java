package org.sectorrent.jlibcrypto.kyber;

import java.security.PublicKey;

public class KyberPublicKey implements PublicKey {

    private byte[] key;

    public KyberPublicKey(byte[] key){
        this.key = key;
    }

    @Override
    public String getAlgorithm(){
        return "Kyber";
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
