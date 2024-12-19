package org.sectorrent.jlibcrypto.sphincs;

import org.sectorrent.jlibcrypto.sphincs.old.GenLeaf;
import org.sectorrent.jlibcrypto.sphincs.old.LeafInfoX1;
import org.sectorrent.jlibcrypto.sphincs.old.Sha256;
import org.sectorrent.jlibcrypto.sphincs.old.SphincsCtx;

import javax.xml.bind.annotation.adapters.HexBinaryAdapter;
import java.security.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.ForkJoinTask;

import static org.sectorrent.jlibcrypto.sphincs.SphincsPlus.CRYPTO_SEED_BYTES;
import static org.sectorrent.jlibcrypto.sphincs.SphincsPlus.SPX_N;
import static org.sectorrent.jlibcrypto.sphincs.SphincsPlusPrivateKey.SPX_SK_BYTES;
import static org.sectorrent.jlibcrypto.sphincs.SphincsPlusPublicKey.SPX_PK_BYTES;

public class SphincsPlusKeyPairGenerator extends KeyPairGeneratorSpi {



    public static final int SPX_N = 16; // Hash output length in bytes

    public static final int SPX_FULL_HEIGHT = 66; /* Height of the hypertree. */
    public static final int SPX_D = 22; // Number of subtree layers

    public static final int SPX_FORS_HEIGHT = 6;
    public static final int SPX_FORS_TREES = 33;
    public static final int SPX_WOTS_W = 16;

    public static final int SPX_ADDR_BYTES = 32;
    public static final int SPX_WOTS_LOGW = SPX_WOTS_W == 256 ? 8 : 4;

    public static final int SPX_WOTS_LEN1 = (8*SPX_N/SPX_WOTS_LOGW); // 32

    public static final int SPX_WOTS_LEN2 = len2(); // 3

    public static final int SPX_WOTS_LEN = (SPX_WOTS_LEN1+SPX_WOTS_LEN2); //  35
    public static final int SPX_WOTS_BYTES = (SPX_WOTS_LEN*SPX_N); // 560
    public static final int SPX_WOTS_PK_BYTES = SPX_WOTS_BYTES;

    public static final int SPX_TREE_HEIGHT = (SPX_FULL_HEIGHT/SPX_D);

    public static final int SPX_FORS_MSG_BYTES = ((SPX_FORS_HEIGHT*SPX_FORS_TREES+7)/8); // 25
    public static final int SPX_FORS_BYTES = ((SPX_FORS_HEIGHT+1)*SPX_FORS_TREES*SPX_N);
    public static final int SPX_FORS_PK_BYTES = SPX_N;

    public static final int SPX_BYTES = (SPX_N+SPX_FORS_BYTES+SPX_D*SPX_WOTS_BYTES+SPX_FULL_HEIGHT*SPX_N);

    public static final int SPX_OFFSET_LAYER = 0;   /* The byte used to specify the Merkle tree layer */
    public static final int SPX_OFFSET_TREE = 1;   /* The start of the 8 byte field used to specify the tree */
    public static final int SPX_OFFSET_TYPE = 9;   /* The byte used to specify the hash type (reason) */
    public static final int SPX_OFFSET_KP_ADDR2= 12;  /* The high byte used to specify the key pair (which one-time signature) */
    public static final int SPX_OFFSET_KP_ADDR1 = 13;  /* The low byte used to specify the key pair */
    public static final int SPX_OFFSET_CHAIN_ADDR =17;  /* The byte used to specify the chain address (which Winternitz chain) */
    public static final int SPX_OFFSET_HASH_ADDR = 21;  /* The byte used to specify the hash address (where in the Winternitz chain) */
    public static final int SPX_OFFSET_TREE_HGT = 17;  /* The byte used to specify the height of this node in the FORS or Merkle tree */
    public static final int SPX_OFFSET_TREE_INDEX =  18; /* The start of the 4 byte field used to specify the node in the FORS or Merkle tree */

    public static final int SPX_SHA2 = 1;

    public static final int CRYPTO_SEED_BYTES = 3*SPX_N;

    public static final int SPX_SHA256_BLOCK_BYTES = 64;
    public static final int SPX_SHA256_OUTPUT_BYTES = 32;  /* This does not necessarily equal SPX_N */

    public static final int SPX_SHA512_BLOCK_BYTES = 128;
    public static final int SPX_SHA512_OUTPUT_BYTES = 64;

    public static final int SPX_SHAX_BLOCK_BYTES = SPX_SHA256_BLOCK_BYTES;
    public static final int SPX_SHAX_OUTPUT_BYTES = SPX_SHA256_OUTPUT_BYTES;

    public static final int SPX_SHA256_ADDR_BYTES = 22;

    public static final int SPX_ADDR_TYPE_WOTS = 0;
    public static final int SPX_ADDR_TYPE_WOTSPK = 1;
    public static final int SPX_ADDR_TYPE_HASHTREE = 2;
    public static final int SPX_ADDR_TYPE_FORSTREE = 3;
    public static final int SPX_ADDR_TYPE_FORSPK = 4;
    public static final int SPX_ADDR_TYPE_WOTSPRF = 5;
    public static final int SPX_ADDR_TYPE_FORSPRF = 6;

    static {
        if(SPX_TREE_HEIGHT*SPX_D != SPX_FULL_HEIGHT){
            throw new IllegalStateException("SPX_D should always divide SPX_FULL_HEIGHT");
        }

        if(SPX_SHA256_OUTPUT_BYTES < SPX_N){
            throw new IllegalStateException("Linking against SHA-256 with N larger than 32 bytes is not supported");
        }
    }




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

        //SUDO RANDOM THE SEED BY THE RANDOM GENERATED ON INIT...

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


    public static void seedState(SphincsCtx ctx){
        byte[] block = new byte[SPX_SHA256_BLOCK_BYTES];
        byte[] pubSeed = ctx.getPubSeed();

        for(int i = 0; i < SPX_N; ++i){
            block[i] = pubSeed[i];
        }

        Sha256 hash = new Sha256();
        hash.update(block);
        ctx.setStateSeeded(hash.getState());
    }

    public static void merkleGenRoot(byte[] root, int rootOffset, SphincsCtx ctx){
        byte[] authPath = new byte[SPX_TREE_HEIGHT*SPX_N+SPX_WOTS_BYTES];
        int[] topTreeAddr = new int[8];
        int[] wotsAddr = new int[8];

        setLayerAddr(topTreeAddr, SPX_D-1);
        setLayerAddr(wotsAddr, SPX_D-1);

        merkleSign(authPath, 0, root, rootOffset, ctx, wotsAddr, topTreeAddr, ~0);
    }

    public static void setLayerAddr(int[] addr, int layer){
        if(SPX_OFFSET_LAYER == 0){
            addr[0] = layer;
            return;
        }

        throw new IllegalStateException("Unimplemented bit munging!");
    }

    public static void merkleSign(byte[] sig, int sigOffset, byte[] root, int rootOffset, SphincsCtx ctx, int[] wotsAddr, int[] treeAddr, int idxLeaf){
        LeafInfoX1 info = new LeafInfoX1();
        int[] steps = new int[SPX_WOTS_LEN];
        info.setWotsSig(sig);
        info.setWotsSigOffset(sigOffset);
        chainLengths(steps, root, rootOffset);
        info.setWotsSteps(steps);

        setByte(treeAddr, SPX_OFFSET_TYPE, (byte) SPX_ADDR_TYPE_HASHTREE);
        setByte(info.getPkAddr(), SPX_OFFSET_TYPE, (byte) SPX_ADDR_TYPE_WOTSPK);
        copySubtreeAddr(info.getLeafAddr(), wotsAddr);
        copySubtreeAddr(info.getPkAddr(), wotsAddr);

        info.setWotsSignLeaf(idxLeaf);

        treehashx1(root, rootOffset, sig, sigOffset+SPX_WOTS_BYTES, ctx, idxLeaf, 0, SPX_TREE_HEIGHT, (a, b, c, d) -> wotsGenLeafx1(a, b, c, d, info), treeAddr);
    }

    public static void wotsGenLeafx1(byte[] dest, int destOffset, SphincsCtx ctx, int leafIdx, LeafInfoX1 vInfo){
        LeafInfoX1 info = vInfo;
        int[] leafAddr = info.getLeafAddr();

        int[] pkAddr = info.getPkAddr();
        byte[] pkBuffer = new byte[SPX_WOTS_BYTES];
        int wotsKMask;

        if(leafIdx == info.getWotsSignLeaf()){
            wotsKMask = 0;

        }else{
            wotsKMask = ~0;
        }

        setKeyPairAddr(leafAddr, leafIdx);
        setKeyPairAddr(pkAddr, leafIdx);

        List<ForkJoinTask<Boolean>> thashes = new ArrayList<>();

        int parallelism = 2;
        int stride = (SPX_WOTS_LEN+parallelism-1)/parallelism;
        List<Integer> splits = new ArrayList<>();

        for(int t=0; t < parallelism; t++){
            splits.add(t*stride);
        }

        splits.add(SPX_WOTS_LEN);

        for(int j = 0; j < splits.size()-1; j++){
            int jCopy = j;
            int[] addrs = Arrays.copyOfRange(leafAddr, 0, leafAddr.length);

            if(j == splits.size()-2){
                wotsLoops(splits.get(jCopy), splits.get(jCopy+1), pkBuffer, splits.get(jCopy)*SPX_N, wotsKMask, addrs, info, ctx);

            }else{
                ForkJoinTask<Boolean> task = ForkJoinPool.commonPool().submit(() -> wotsLoops(splits.get(jCopy), splits.get(jCopy+1), pkBuffer, splits.get(jCopy)*SPX_N, wotsKMask, addrs, info, ctx));
                thashes.add(task);
            }
        }

        for(ForkJoinTask<Boolean> hash : thashes){
            hash.join();
        }

        thash(dest, destOffset, pkBuffer, 0, SPX_WOTS_LEN, ctx, pkAddr);
    }

    private static boolean wotsLoops(int start, int end, byte[] buffer, int bufferOffset, int wotsKMask, int[] leafAddr, LeafInfoX1 info, SphincsCtx ctx){
        int[] wotsSteps = info.getWotsSteps();

        for(int i = start; i < end; i++, bufferOffset += SPX_N){
            int wotsK = wotsSteps[i] | wotsKMask;

            setByte(leafAddr, SPX_OFFSET_CHAIN_ADDR, (byte) i);
            setByte(leafAddr, SPX_OFFSET_HASH_ADDR, (byte) 0);
            setByte(leafAddr, SPX_OFFSET_TYPE, (byte) SPX_ADDR_TYPE_WOTSPRF);

            prfAddr(buffer, bufferOffset, ctx, leafAddr);

            setByte(leafAddr, SPX_OFFSET_TYPE, (byte) SPX_ADDR_TYPE_WOTS);

            wotsComponent(buffer, bufferOffset, leafAddr, i, wotsK, info, ctx);
        }

        return true;
    }

    private static boolean wotsComponent(byte[] buffer, int off, int[] addrs, int i, int wotsK, LeafInfoX1 info, SphincsCtx ctx){
        for(int k = 0;; k++){
            if(k == wotsK){
                System.arraycopy(buffer, off, info.getWotsSig(), info.getWotsSigOffset()+i*SPX_N, SPX_N);
            }

            if(k == SPX_WOTS_W-1){
                break;
            }

            setByte(addrs, SPX_OFFSET_HASH_ADDR, (byte) k);
            thash(buffer, off, buffer, off, 1, ctx, addrs);
        }
        return true;
    }

    public static void wotsChecksum(int[] csumBaseW, int offset){
        int[] msgBaseW = csumBaseW;
        int csum = 0;
        byte[] csumBytes = new byte[(SPX_WOTS_LEN2*SPX_WOTS_LOGW+7)/8];

        for(int i = 0; i < SPX_WOTS_LEN1; i++){
            csum += SPX_WOTS_W-1-msgBaseW[i];
        }

        csum = csum << ((8-((SPX_WOTS_LEN2*SPX_WOTS_LOGW)%8))%8);
        ullToBytes(csumBytes, csum);
        baseW(csumBaseW, offset, SPX_WOTS_LEN2, csumBytes, 0);
    }

    public static void setKeyPairAddr(int[] addr, int keypair){
        if(SPX_FULL_HEIGHT/SPX_D > 8){
            setByte(addr, SPX_OFFSET_KP_ADDR2, (byte) (keypair >> 8));
        }
        setByte(addr, SPX_OFFSET_KP_ADDR1, (byte) keypair);
    }

    public static void prfAddr(byte[] out, int outOffset, SphincsCtx ctx, int[] addr){
        byte[] sha2State = new byte[40];
        byte[] buf = new byte[SPX_SHA256_ADDR_BYTES+SPX_N];

        System.arraycopy(ctx.getStateSeeded(), 0, sha2State, 0, 40);

        System.arraycopy(intsToBytes(addr, SPX_SHA256_ADDR_BYTES), 0, buf, 0, SPX_SHA256_ADDR_BYTES);
        System.arraycopy(ctx.getSkSeed(), 0, buf, SPX_SHA256_ADDR_BYTES, SPX_N);

        Sha256 res = new Sha256(sha2State, 64);
        res.update(buf);
        byte[] state = res.digest();

        System.arraycopy(state, 0, out, outOffset, SPX_N);
    }

    public static void chainLengths(int[] lengths, byte[] msg, int offset){
        baseW(lengths, 0, SPX_WOTS_LEN1, msg, offset);
        wotsChecksum(lengths, SPX_WOTS_LEN1);
    }

    public static void baseW(int[] output, int outputOffset, int out_len,  byte[] input, int inputOffset){
        int in = 0;
        int out = 0;
        int total = 0;
        int bits = 0;
        int consumed;

        for(consumed = 0; consumed < out_len; consumed++){
            if(bits == 0){
                total = input[inputOffset+in] & 0xFF;
                in++;
                bits += 8;
            }

            bits -= SPX_WOTS_LOGW;
            output[outputOffset+out] = (total >> bits) & (SPX_WOTS_W-1);
            out++;
        }
    }

    public static void ullToBytes(byte[] out, int in){
        for(int i = out.length-1; i >= 0; i--){
            out[i] = (byte)in;
            in = in >> 8;
        }
    }

    public static void setByte(int[] out, int byteOffset, byte val){
        int index = byteOffset/4;
        int mod = byteOffset%4;
        int prior = out[index];
        out[index] = (prior & ~(0xFF << (mod*8))) | ((val & 0xFF) << (mod*8));
    }

    public static byte getByte(int[] in, int byteOffset){
        int index = byteOffset/4;
        int mod = byteOffset%4;
        return (byte) (in[index] >> (mod*8));
    }

    public static void copySubtreeAddr(int[] out, int[] in){
        System.arraycopy(in, 0, out, 0, 2);
        setByte(out, 8+SPX_OFFSET_TREE-1, getByte(in, 8+SPX_OFFSET_TREE-1));
    }

    public static void treehashx1(byte[] root, int rootOffset, byte[] authPath, int auth_pathOffset, SphincsCtx ctx, int leafIdx, int idxOffset, int treeHeight, GenLeaf genLeaf, int[] treeAddr){
        byte[] stack = new byte[treeHeight*SPX_N];

        int maxIdx = (1 << treeHeight)-1;
        for(int idx = 0;; idx++){
            byte[] current = new byte[2*SPX_N];
            genLeaf.apply(current, SPX_N, ctx, idx+idxOffset);

            int internalIdxOffset = idxOffset;
            int internalIdx = idx;
            int internalLeaf = leafIdx;
            int h;
            for(h = 0;; h++, internalIdx >>= 1, internalLeaf >>= 1){
                if(h == treeHeight){
                    System.arraycopy(current, SPX_N, root, rootOffset, SPX_N);
                    return;
                }

                if((internalIdx ^ internalLeaf) == 0x01){
                    System.arraycopy(current, SPX_N, authPath, auth_pathOffset+h*SPX_N, SPX_N);
                }

                if((internalIdx & 1) == 0 && idx < maxIdx){
                    break;
                }

                internalIdxOffset >>= 1;
                setTreeHeight(treeAddr, h+1);
                setTreeIndex(treeAddr, internalIdx/2+internalIdxOffset);

                System.arraycopy(stack, h*SPX_N, current, 0, SPX_N);
                thash(current, 1*SPX_N, current, 0, 2, ctx, treeAddr);
            }

            System.arraycopy(current, SPX_N, stack, h*SPX_N, SPX_N);
        }
    }

    public static void thash(byte[] out, int outOffset, byte[] in, int inOffset, int inblocks, SphincsCtx ctx, int[] addr){
        byte[] buf = new byte[SPX_N+SPX_SHA256_ADDR_BYTES+inblocks*SPX_N];
        byte[] bitmask = new byte[inblocks*SPX_N];
        byte[] sha2_state = new byte[40];

        System.arraycopy(ctx.getPubSeed(), 0, buf, 0, SPX_N);
        System.arraycopy(intsToBytes(addr, SPX_SHA256_ADDR_BYTES), 0, buf, SPX_N, SPX_SHA256_ADDR_BYTES);
        mgf1_256(bitmask, 0, inblocks*SPX_N, buf, SPX_N+SPX_SHA256_ADDR_BYTES);

        System.arraycopy(ctx.getStateSeeded(), 0, sha2_state, 0, 40);

        for(int i = 0; i < inblocks*SPX_N; i++){
            buf[SPX_N+SPX_SHA256_ADDR_BYTES+i] = (byte)(in[inOffset+i] ^ bitmask[i]);
        }

        Sha256 res = new Sha256(sha2_state, 64);
        res.update(buf, SPX_N, SPX_SHA256_ADDR_BYTES+inblocks*SPX_N);
        byte[] digest = res.digest();
        System.arraycopy(digest, 0, out, outOffset, SPX_N);
    }

    private static byte[] intsToBytes(int[] in, int bytes){
        int intCount = (bytes+3)/4;
        byte[] res = new byte[bytes+4];

        for(int i = 0; i < intCount; i++){
            res[i*4] = (byte)in[i];
            res[i*4+1] = (byte)(in[i] >> 8);
            res[i*4+2] = (byte)(in[i] >> 16);
            res[i*4+3] = (byte)(in[i] >> 24);
        }

        return Arrays.copyOfRange(res, 0, bytes);
    }

    public static void setTreeHeight(int[] addr, int treeHeight){
        setByte(addr, SPX_OFFSET_TREE_HGT, (byte) treeHeight);
    }

    public static void setTreeIndex(int[] addr, int treeIndex){
        setByte(addr, SPX_OFFSET_TREE_INDEX+3, (byte) treeIndex);
        setByte(addr, SPX_OFFSET_TREE_INDEX+2, (byte) (treeIndex >> 8));
        setByte(addr, SPX_OFFSET_TREE_INDEX+1, (byte) (treeIndex >> 16));
        setByte(addr, SPX_OFFSET_TREE_INDEX+0, (byte) (treeIndex >> 24));
    }

    public static void mgf1_256(byte[] out, int outIndex, int outlen, byte[] in, int inlen){
        byte[] inbuf = new byte[inlen+4];
        byte[] outbuf = new byte[SPX_SHA256_OUTPUT_BYTES];
        int i;

        System.arraycopy(in, 0, inbuf, 0, inlen);

        for(i = 0; (i+1)*SPX_SHA256_OUTPUT_BYTES <= outlen; i++){
            u32ToBytes(inbuf, inlen, i);
            sha256(out, outIndex, inbuf);
            outIndex += SPX_SHA256_OUTPUT_BYTES;
        }

        if(outlen > i*SPX_SHA256_OUTPUT_BYTES){
            u32ToBytes(inbuf, inlen, i);
            sha256(outbuf, 0, inbuf);
            System.arraycopy(outbuf, 0, out, outIndex, outlen-i*SPX_SHA256_OUTPUT_BYTES);
        }
    }

    public static void u32ToBytes(byte[] out, int outOffset, int in){
        out[outOffset+0] = (byte)(in >> 24);
        out[outOffset+1] = (byte)(in >> 16);
        out[outOffset+2] = (byte)(in >> 8);
        out[outOffset+3] = (byte)in;
    }






    private static final ThreadLocal<MessageDigest> sha2 = ThreadLocal.withInitial(() -> getInstance());

    private static MessageDigest getInstance(){
        try{
            return MessageDigest.getInstance("SHA-256");

        }catch(NoSuchAlgorithmException e){
            throw new RuntimeException(e);
        }
    }

    public static void sha256(byte[] out, int outIndex, byte[] in, int inStart, int inSize){
        sha256(out, outIndex, Arrays.copyOfRange(in, inStart, inStart+inSize));
    }

    public static void sha256(byte[] out, int outIndex, byte[] in){
        MessageDigest md = sha2.get();
        md.update(in);
        byte[] res = md.digest();
        System.arraycopy(res, 0, out, outIndex, res.length);
    }

    public static MessageDigest newSha256(){
        try{
            return MessageDigest.getInstance("SHA-256");

        }catch(NoSuchAlgorithmException e){
            throw new RuntimeException(e);
        }
    }

    public static final int len2(){
        if(SPX_WOTS_W == 256){
            if(SPX_N <= 1){
                return 1;

            }else if(SPX_N <= 256){
                return 2;
            }

            throw new IllegalStateException("Did not precompute SPX_WOTS_LEN2 for n outside {2, .., 256}");

        }else if(SPX_WOTS_W == 16){
            if(SPX_N <= 8){
                return 2;

            }else if(SPX_N <= 136){
                return 3;

            }else if(SPX_N <= 256){
                return 4;
            }

            throw new IllegalStateException("Did not precompute SPX_WOTS_LEN2 for n outside {2, .., 256}");
        }

        throw new IllegalStateException("Unknown SPX_WOTS_W");
    }
}
