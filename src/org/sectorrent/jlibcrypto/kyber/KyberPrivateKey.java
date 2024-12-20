package org.sectorrent.jlibcrypto.kyber;

import java.security.PrivateKey;

public class KyberPrivateKey implements PrivateKey {

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
        return new byte[0];
    }
}
