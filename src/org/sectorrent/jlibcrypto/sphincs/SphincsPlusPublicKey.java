package org.sectorrent.jlibcrypto.sphincs;

import java.security.PublicKey;

import static org.sectorrent.jlibcrypto.sphincs.SphincsPlus.SPX_N;

public class SphincsPlusPublicKey implements PublicKey {

    public static final int SPX_PK_BYTES = (2*SPX_N);

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
