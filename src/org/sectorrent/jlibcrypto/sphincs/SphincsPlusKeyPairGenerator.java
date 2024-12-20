package org.sectorrent.jlibcrypto.sphincs;

import javax.xml.bind.annotation.adapters.HexBinaryAdapter;
import java.security.*;

import static org.sectorrent.jlibcrypto.sphincs.SphincsPlus.*;

public class SphincsPlusKeyPairGenerator extends KeyPairGeneratorSpi {

    private SecureRandom random;
    private int keySize;

    public SphincsPlusKeyPairGenerator(){
        this.keySize = 128;
    }

    @Override
    public void initialize(int keysize, SecureRandom random){
        this.keySize = keysize;
        this.random = random;
    }

    @Override
    public KeyPair generateKeyPair(){
        //return generateKeys(random.generateSeed(keySize));
        return generateKeys(hexToBytes("133038bbb8225cc1a5bff68f704de766ddbd315b61cd7a66006cdb6b99a116f3df3be01d842391100e6c41a42ed126a7"));
    }

    //TEMPORARY
    public static byte[] hexToBytes(String hexString){
        HexBinaryAdapter adapter = new HexBinaryAdapter();
        return adapter.unmarshal(hexString);
    }
}
