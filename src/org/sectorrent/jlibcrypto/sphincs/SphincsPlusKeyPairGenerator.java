package org.sectorrent.jlibcrypto.sphincs;

import org.sectorrent.jlibcrypto.sphincs.utils.*;

import javax.xml.bind.annotation.adapters.HexBinaryAdapter;
import java.security.*;
import java.util.Arrays;

//import static org.sectorrent.jlibcrypto.sphincs.SphincsPlus.*;
import static org.sectorrent.jlibcrypto.sphincs.SphincsPlusParams.*;

public class SphincsPlusKeyPairGenerator extends KeyPairGeneratorSpi {

    private SecureRandom random;
    private int keySize;

    @Override
    public void initialize(int keysize, SecureRandom random){
        this.keySize = keysize;
        this.random = random;
    }

    @Override
    public KeyPair generateKeyPair(){
        SphincsPlusPKI sphincsPlusPKI = generateKeys();
        return new KeyPair(sphincsPlusPKI.getPublicKey(), sphincsPlusPKI.getPrivateKey());
    }

    //TEMPORARY
    private byte[] hexToBytes(String hexString){
        HexBinaryAdapter adapter = new HexBinaryAdapter();
        return adapter.unmarshal(hexString);
    }

    private SphincsPlusPKI generateKeys(){
        byte[] publicKey = new byte[SPX_PK_BYTES];
        byte[] privateKey = new byte[SPX_SK_BYTES];

        SphincsCtx ctx = new SphincsCtx();
        System.arraycopy(random.generateSeed(keySize), 0, privateKey, 0, CRYPTO_SEED_BYTES);
        //System.arraycopy(hexToBytes("133038bbb8225cc1a5bff68f704de766ddbd315b61cd7a66006cdb6b99a116f3df3be01d842391100e6c41a42ed126a7"), 0, privateKey, 0, CRYPTO_SEED_BYTES);
        System.arraycopy(privateKey, 2*SPX_N, publicKey, 0, SPX_N);
        ctx.setPubSeed(Arrays.copyOfRange(publicKey, 0, SPX_N));
        ctx.setSkSeed(Arrays.copyOfRange(privateKey, 0, SPX_N));

        ctx.seedState();
        merkleGenRoot(privateKey, 3*SPX_N, ctx);
        System.arraycopy(privateKey, 3*SPX_N, publicKey, SPX_N, SPX_N);

        return new SphincsPlusPKI(new SphincsPlusPublicKey(publicKey), new SphincsPlusPrivateKey(privateKey));
    }

    private void merkleGenRoot(byte[] root, int rootOffset, SphincsCtx ctx){
        byte[] authPath = new byte[SPX_TREE_HEIGHT*SPX_N+SPX_WOTS_BYTES];
        int[] topTreeAddr = new int[8];
        int[] wotsAddr = new int[8];

        AddressUtils.setLayerAddress(topTreeAddr, SPX_D-1);
        AddressUtils.setLayerAddress(wotsAddr, SPX_D-1);

        merkleSign(authPath, 0, root, rootOffset, ctx, wotsAddr, topTreeAddr, ~0);
    }

    private void merkleSign(byte[] sig, int sigOffset, byte[] root, int rootOffset, SphincsCtx ctx, int[] wotsAddr, int[] treeAddr, int idxLeaf){
        LeafInfoX1 info = new LeafInfoX1();
        int[] steps = new int[SPX_WOTS_LEN];
        info.setWotsSig(sig);
        info.setWotsSigOffset(sigOffset);
        Wots.chainLengths(steps, root, rootOffset);
        info.setWotsSteps(steps);

        ByteUtils.setByte(treeAddr, SPX_OFFSET_TYPE, (byte) SPX_ADDR_TYPE_HASHTREE);
        ByteUtils.setByte(info.getPkAddress(), SPX_OFFSET_TYPE, (byte) SPX_ADDR_TYPE_WOTSPK);
        AddressUtils.copySubTreeAddress(info.getLeafAddress(), wotsAddr);
        AddressUtils.copySubTreeAddress(info.getPkAddress(), wotsAddr);

        info.setWotsSignLeaf(idxLeaf);

        TreeHash.treeHashX1(root, rootOffset, sig, sigOffset+SPX_WOTS_BYTES, ctx, idxLeaf, 0, SPX_TREE_HEIGHT, (a, b, c, d) -> Wots.wotsGenLeafx1(a, b, c, d, info), treeAddr);
    }
}
