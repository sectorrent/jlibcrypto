package org.sectorrent.jlibcrypto.kyber;

import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;

public class Kyber1024KeyPairGenerator extends KeyPairGeneratorSpi {

    private SecureRandom random;
    private int keySize;

    @Override
    public void initialize(int keysize, SecureRandom random){
        if(keysize != 768){
            throw new InvalidParameterException("Kyber key size must be 1024.");
        }

        this.random = random;
    }

    @Override
    public KeyPair generateKeyPair(){
        return null;
    }
}
