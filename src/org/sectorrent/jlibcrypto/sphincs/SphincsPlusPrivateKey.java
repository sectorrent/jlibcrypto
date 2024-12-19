package org.sectorrent.jlibcrypto.sphincs;

import java.security.PrivateKey;

import static org.sectorrent.jlibcrypto.sphincs.SphincsPlus.SPX_N;
import static org.sectorrent.jlibcrypto.sphincs.SphincsPlusPublicKey.SPX_PK_BYTES;

public class SphincsPlusPrivateKey implements PrivateKey {

    public static final int SPX_SK_BYTES = (2*SPX_N+SPX_PK_BYTES);

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
