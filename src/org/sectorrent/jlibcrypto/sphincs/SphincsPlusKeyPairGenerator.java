package org.sectorrent.jlibcrypto.sphincs;

import org.sectorrent.jlibcrypto.sphincs.utils.SphincsCtx;

import javax.xml.bind.annotation.adapters.HexBinaryAdapter;
import java.security.*;
import java.util.Arrays;

import static org.sectorrent.jlibcrypto.sphincs.SphincsPlus.*;
import static org.sectorrent.jlibcrypto.sphincs.SphincsPlusPrivateKey.SPX_SK_BYTES;
import static org.sectorrent.jlibcrypto.sphincs.SphincsPlusPublicKey.SPX_PK_BYTES;
import static org.sectorrent.jlibcrypto.sphincs.old.SphincsPlus.merkleGenRoot;

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
        byte[] publicKey = new byte[SPX_PK_BYTES];
        byte[] privateKey = new byte[SPX_SK_BYTES];

        SphincsCtx ctx = new SphincsCtx();
        System.arraycopy(hexToBytes("133038bbb8225cc1a5bff68f704de766ddbd315b61cd7a66006cdb6b99a116f3df3be01d842391100e6c41a42ed126a7"), 0, privateKey, 0, CRYPTO_SEED_BYTES);
        System.arraycopy(privateKey, 2*SPX_N, publicKey, 0, SPX_N);
        ctx.setPubSeed(Arrays.copyOfRange(publicKey, 0, SPX_N));
        ctx.setSkSeed(Arrays.copyOfRange(privateKey, 0, SPX_N));

        seedState(ctx);
        merkleGenRoot(privateKey, 3*SPX_N, ctx);
        System.arraycopy(privateKey, 3*SPX_N, publicKey, SPX_N, SPX_N);

        return new KeyPair(new SphincsPlusPublicKey(publicKey), new SphincsPlusPrivateKey(privateKey));
    }

    //TEMPORARY
    public static byte[] hexToBytes(String hexString){
        HexBinaryAdapter adapter = new HexBinaryAdapter();
        return adapter.unmarshal(hexString);
    }
}
