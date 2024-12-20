package org.sectorrent.jlibcrypto.sphincs;

import org.sectorrent.jlibcrypto.hash.SHA256;
import org.sectorrent.jlibcrypto.sphincs.utils.*;

import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.ForkJoinTask;

import static org.sectorrent.jlibcrypto.sphincs.SphincsPlusParams.*;

public class SphincsPlus {

    private static final ThreadLocal<MessageDigest> sha2 = ThreadLocal.withInitial(() -> getInstance());

    private byte[] key;
    private byte[] message;

    public SphincsPlus(byte[] key){
        this.key = key;
    }

    public byte[] sign(){
        byte[] sig = new byte[SPX_BYTES+message.length];
        SphincsCtx ctx = new SphincsCtx();
        byte[] skPrf = Arrays.copyOfRange(key, SPX_N,  key.length);;
        byte[] pk = Arrays.copyOfRange(key, 2*SPX_N, key.length);

        byte[] optrand = new byte[SPX_N];
        byte[] mhash = new byte[SPX_FORS_MSG_BYTES];
        byte[] root = new byte[SPX_N];
        long[] tree = new long[1];
        int[] idxLeaf = new int[1];
        int[] wotsAddr = new int[8];
        int[] treeAddr = new int[8];

        ctx.setPubSeed(Arrays.copyOfRange(key, 2*SPX_N, 2*SPX_N+SPX_N));
        ctx.setSkSeed(Arrays.copyOfRange(key, 0, SPX_N));

        ctx.seedState();

        setByte(wotsAddr, SPX_OFFSET_TYPE, (byte) SPX_ADDR_TYPE_WOTS);
        setByte(treeAddr, SPX_OFFSET_TYPE, (byte) SPX_ADDR_TYPE_HASHTREE);

        genMessageRandom(sig, skPrf, optrand, message);

        hashMessage(mhash, tree, idxLeaf, sig, pk, message);
        int sigOffset = SPX_N;

        setTreeAddr(wotsAddr, tree[0]);
        setKeyPairAddr(wotsAddr, idxLeaf[0]);

        forsSign(sig, sigOffset, root, mhash, ctx, wotsAddr);
        sigOffset += SPX_FORS_BYTES;

        for(int i = 0; i < SPX_D; i++){
            setLayerAddr(treeAddr, i);
            setTreeAddr(treeAddr, tree[0]);

            copySubtreeAddr(wotsAddr, treeAddr);
            setKeyPairAddr(wotsAddr, idxLeaf[0]);

            merkleSign(sig, sigOffset, root, 0, ctx, wotsAddr, treeAddr, idxLeaf[0]);

            sigOffset += SPX_WOTS_BYTES+SPX_TREE_HEIGHT*SPX_N;

            idxLeaf[0] = ((int)tree[0] & ((1 << SPX_TREE_HEIGHT)-1));
            tree[0] = tree[0] >> SPX_TREE_HEIGHT;
        }

        System.arraycopy(message, 0, sig, SPX_BYTES, message.length);

        return sig;
    }

    public void update(byte b){
        update(new byte[]{ b }, 0, 1);
    }

    public void update(byte[] b, int off, int len){
        if(off > len){
            throw new InvalidParameterException("Offset is greater than length");
        }

        if(message == null){
            message = new byte[len-off];
            System.arraycopy(b, off, message, 0, message.length);
            return;
        }

        byte[] m = new byte[message.length+len-off];
        System.arraycopy(message, 0, m, 0, m.length);
        System.arraycopy(b, off, m, message.length, len-off);
        message = m;
    }

    public boolean verify(byte[] sig){
        SphincsCtx ctx = new SphincsCtx();
        byte[] pubRoot = Arrays.copyOfRange(key, SPX_N, key.length);
        byte[] mhash = new byte[SPX_FORS_MSG_BYTES];
        byte[] wotsPk = new byte[SPX_WOTS_BYTES];
        byte[] root = new byte[SPX_N];
        byte[] leaf = new byte[SPX_N];
        long[] tree = new long[1];
        int[] idxLeaf = new int[1];
        int[] wotsAddr = new int[8];
        int[] treeAddr = new int[8];
        int[] wotsPkAddr = new int[8];
        byte[] m = Arrays.copyOfRange(sig, SPX_BYTES, sig.length);
        int sigOffset = 0;

        if(sig.length <= SPX_BYTES){
            throw new IllegalStateException("Signature too short!");
        }

        System.arraycopy(key, 0, ctx.getPubSeed(), 0, SPX_N);

        ctx.seedState();

        setByte(wotsAddr, SPX_OFFSET_TYPE, (byte) SPX_ADDR_TYPE_WOTS);
        setByte(treeAddr, SPX_OFFSET_TYPE, (byte) SPX_ADDR_TYPE_HASHTREE);
        setByte(wotsPkAddr, SPX_OFFSET_TYPE, (byte) SPX_ADDR_TYPE_WOTSPK);

        hashMessage(mhash, tree, idxLeaf, sig, key, m);
        sigOffset += SPX_N;

        setTreeAddr(wotsAddr, tree[0]);
        setKeyPairAddr(wotsAddr, idxLeaf[0]);

        forsPkFromSig(root, sig, sigOffset, mhash, ctx, wotsAddr);
        sigOffset += SPX_FORS_BYTES;

        for(int i = 0; i < SPX_D; i++){
            setLayerAddr(treeAddr, i);
            setTreeAddr(treeAddr, tree[0]);

            copySubtreeAddr(wotsAddr, treeAddr);
            setKeyPairAddr(wotsAddr, idxLeaf[0]);

            copyKeypairAddr(wotsPkAddr, wotsAddr);

            wotsPkFromSig(wotsPk, sig, sigOffset, root, ctx, wotsAddr);
            sigOffset += SPX_WOTS_BYTES;

            thash(leaf, 0, wotsPk, 0, SPX_WOTS_LEN, ctx, wotsPkAddr);

            computeRoot(root, 0, leaf, idxLeaf[0], 0, sig, sigOffset, SPX_TREE_HEIGHT, ctx, treeAddr);
            sigOffset += SPX_TREE_HEIGHT*SPX_N;

            idxLeaf[0] = (int)(tree[0] & ((1 << SPX_TREE_HEIGHT)-1));
            tree[0] = tree[0] >> SPX_TREE_HEIGHT;
        }

        if(!Arrays.equals(root, pubRoot)){
            throw new IllegalStateException("Invalid signature!");
        }

        return Arrays.equals(Arrays.copyOfRange(sig, SPX_BYTES, sig.length), message);
    }

    protected static void merkleGenRoot(byte[] root, int rootOffset, SphincsCtx ctx){
        byte[] authPath = new byte[SPX_TREE_HEIGHT*SPX_N+SPX_WOTS_BYTES];
        int[] topTreeAddr = new int[8];
        int[] wotsAddr = new int[8];

        setLayerAddr(topTreeAddr, SPX_D-1);
        setLayerAddr(wotsAddr, SPX_D-1);

        merkleSign(authPath, 0, root, rootOffset, ctx, wotsAddr, topTreeAddr, ~0);
    }

    private void genMessageRandom(byte[] R, byte[] skPrf, byte[] optrand, byte[] m){
        byte[] buf = new byte[SPX_SHAX_BLOCK_BYTES+SPX_SHAX_OUTPUT_BYTES];

        if(SPX_N > SPX_SHAX_BLOCK_BYTES){
            throw new IllegalStateException("Currently only supports SPX_N of at most SPX_SHAX_BLOCK_BYTES");
        }

        for(int i = 0; i < SPX_N; i++){
            buf[i] = (byte) (0x36 ^ skPrf[i]);
        }
        for(int j = 0; j < SPX_SHAX_BLOCK_BYTES-SPX_N; j++){
            buf[SPX_N+j] = (byte)0x36;
        }

        MessageDigest hash = getInstance();
        hash.update(buf, 0, 64);

        System.arraycopy(optrand, 0, buf, 0, SPX_N);

        if(SPX_N+m.length < SPX_SHAX_BLOCK_BYTES){
            System.arraycopy(m, 0, buf, SPX_N, m.length);
            hash.update(buf, 0, m.length+SPX_N);
            byte[]  digest = hash.digest();
            System.arraycopy(digest, 0, buf, SPX_SHAX_BLOCK_BYTES, 32);
        }else{
            int initialCopySize = SPX_SHAX_BLOCK_BYTES-SPX_N;
            System.arraycopy(m, 0, buf, SPX_N, initialCopySize);
            hash.update(buf, 0, 64);
            hash.update(m, initialCopySize, m.length-initialCopySize);
            byte[] digest = hash.digest();
            System.arraycopy(digest, 0, buf, SPX_SHAX_BLOCK_BYTES, 32);
        }

        for(int i = 0; i < SPX_N; i++){
            buf[i] = (byte) (0x5c ^ skPrf[i]);
        }

        for(int j=0; j < SPX_SHAX_BLOCK_BYTES-SPX_N; j++){
            buf[SPX_N+j] = 0x5c;
        }

        MessageDigest md = sha2.get();
        md.update(Arrays.copyOfRange(buf, 0, SPX_SHAX_BLOCK_BYTES+SPX_SHAX_OUTPUT_BYTES));
        byte[] res = md.digest();
        System.arraycopy(res, 0, buf, 0, res.length);

        System.arraycopy(buf, 0, R, 0, SPX_N);
    }

    private void hashMessage(byte[] digest, long[] tree, int[] leafIdx, byte[] R, byte[] pk, byte[] m){
        int SPX_TREE_BITS = (SPX_TREE_HEIGHT*(SPX_D-1)); // 3*21 = 63
        int SPX_TREE_BYTES = ((SPX_TREE_BITS+7)/8); // 8
        int SPX_LEAF_BITS = SPX_TREE_HEIGHT; // 3
        int SPX_LEAF_BYTES = ((SPX_LEAF_BITS+7)/8); // 1
        int SPX_DGST_BYTES = (SPX_FORS_MSG_BYTES+SPX_TREE_BYTES+SPX_LEAF_BYTES); // 25+8+1 = 34

        byte[] seed = new byte[2*SPX_N+SPX_SHAX_OUTPUT_BYTES];

        if((SPX_SHAX_BLOCK_BYTES & (SPX_SHAX_BLOCK_BYTES-1)) != 0){
            throw new IllegalStateException("Assumes that SPX_SHAX_BLOCK_BYTES is a power of 2");
        }

        int SPX_INBLOCKS = (((SPX_N+SPX_PK_BYTES+SPX_SHAX_BLOCK_BYTES-1) & -SPX_SHAX_BLOCK_BYTES)/SPX_SHAX_BLOCK_BYTES);
        byte[] inbuf = new byte[SPX_INBLOCKS*SPX_SHAX_BLOCK_BYTES];

        byte[] buf = new byte[SPX_DGST_BYTES];
        int bufp = 0;

        System.arraycopy(R, 0, inbuf, 0, SPX_N);
        System.arraycopy(pk, 0, inbuf, SPX_N, SPX_PK_BYTES);

        if(SPX_N+SPX_PK_BYTES+m.length < SPX_INBLOCKS*SPX_SHAX_BLOCK_BYTES){
            System.arraycopy(m, 0, inbuf, SPX_N+SPX_PK_BYTES, m.length);

            MessageDigest md = sha2.get();
            md.update(Arrays.copyOfRange(inbuf, 0, SPX_N+SPX_PK_BYTES+m.length));
            byte[] res = md.digest();
            System.arraycopy(res, 0, seed, 2*SPX_N, res.length);

        }else{
            int initialCopySize = SPX_INBLOCKS*SPX_SHAX_BLOCK_BYTES-SPX_N-SPX_PK_BYTES;
            System.arraycopy(m, 0, inbuf, SPX_N+SPX_PK_BYTES, initialCopySize);

            try{
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                md.update(inbuf);
                md.update(m, initialCopySize, m.length-initialCopySize);
                byte[] res = md.digest();
                System.arraycopy(res, 0, seed, 2*SPX_N, 32);

            }catch(Exception e){
                throw new RuntimeException(e);
            }
        }

        System.arraycopy(R,  0, seed, 0, SPX_N);
        System.arraycopy(pk,  0, seed, SPX_N, SPX_N);

        mgf1_256(buf, bufp, SPX_DGST_BYTES, seed, 2*SPX_N+SPX_SHAX_OUTPUT_BYTES);

        System.arraycopy(buf, bufp, digest, 0, SPX_FORS_MSG_BYTES);
        bufp += SPX_FORS_MSG_BYTES;

        if(SPX_TREE_BITS > 64){
            throw new IllegalStateException("For given height and depth, 64 bits cannot represent all subtrees");
        }

        tree[0] = bytesToUll(buf, bufp, SPX_TREE_BYTES);
        tree[0] &= ((1L << SPX_TREE_BITS)-1);
        bufp += SPX_TREE_BYTES;

        leafIdx[0] = (int) bytesToUll(buf, bufp, SPX_LEAF_BYTES);
        leafIdx[0] &= ((1 << SPX_LEAF_BITS)-1);
    }

    private void setTreeAddr(int[] addr, long tree){
        if((SPX_TREE_HEIGHT*(SPX_D-1)) > 64){
            throw new IllegalStateException("Subtree addressing is currently limited to at most 2^64 trees");
        }

        for(int i = 0; i < 8; i++){
            setByte(addr, SPX_OFFSET_TREE+i, (byte) (tree >> (56-8*i)));
        }
    }

    private void forsSign(byte[] sig, int sigOffset, byte[] pk, byte[] m, SphincsCtx ctx, int[] forsAddr){
        int[] indices = new int[SPX_FORS_TREES];
        byte[] roots = new byte[SPX_FORS_TREES*SPX_N];
        int[] forsTreeAddr = new int[8];
        ForsGenLeafInfo forsInfo = new ForsGenLeafInfo();
        int[] forsLeafAddr = forsInfo.getLeafAddrX();
        int[] forsPkAddr = new int[8];
        int idxOffset;

        copyKeypairAddr(forsTreeAddr, forsAddr);
        copyKeypairAddr(forsLeafAddr, forsAddr);

        copyKeypairAddr(forsPkAddr, forsAddr);
        setByte(forsPkAddr, SPX_OFFSET_TYPE, (byte) SPX_ADDR_TYPE_FORSPK);

        messageToIndices(indices, m);

        for(int i = 0; i < SPX_FORS_TREES; i++){
            idxOffset = i*(1 << SPX_FORS_HEIGHT);

            setTreeHeight(forsTreeAddr, 0);
            setTreeIndex(forsTreeAddr, indices[i]+idxOffset);
            setByte(forsTreeAddr, SPX_OFFSET_TYPE, (byte) SPX_ADDR_TYPE_FORSPRF);

            prfAddr(sig, sigOffset, ctx, forsTreeAddr);
            setByte(forsTreeAddr, SPX_OFFSET_TYPE, (byte) SPX_ADDR_TYPE_FORSTREE);
            sigOffset += SPX_N;

            treeHashx1(roots, i*SPX_N, sig, sigOffset, ctx, indices[i], idxOffset, SPX_FORS_HEIGHT, (a, b, c, d) -> forsGenLeafx1(a, b, c, d, forsInfo), forsTreeAddr);

            sigOffset += SPX_N*SPX_FORS_HEIGHT;
        }

        thash(pk, 0, roots, 0, SPX_FORS_TREES, ctx, forsPkAddr);
    }

    private long bytesToUll(byte[] in, int inOffset, int inlen){
        long retval = 0;

        for(int i = 0; i < inlen; i++){
            retval |= (in[inOffset+i] & 0xFFL) << (8*(inlen-1-i));
        }
        return retval;
    }

    private void copyKeypairAddr(int[] out, int[] in){
        out[0] = in[0];
        out[1] = in[1];
        setByte(out, SPX_OFFSET_TREE+8-1, getByte(in, SPX_OFFSET_TREE+8-1));

        if(SPX_FULL_HEIGHT/SPX_D > 8){
            setByte(out, SPX_OFFSET_KP_ADDR2, getByte(in, SPX_OFFSET_KP_ADDR2));
        }

        setByte(out, SPX_OFFSET_KP_ADDR1, getByte(in, SPX_OFFSET_KP_ADDR1));
    }

    private void messageToIndices(int[] indices, byte[] m){
        int offset = 0;

        for(int i = 0; i < SPX_FORS_TREES; i++){
            indices[i] = 0;

            for(int j = 0; j < SPX_FORS_HEIGHT; j++){
                indices[i] ^= ((m[offset >> 3] >> (offset & 0x7)) & 0x1) << j;
                offset++;
            }
        }
    }

    private void forsPkFromSig(byte[] pk, byte[] sig, int sigOffset, byte[] m, SphincsCtx ctx, int[] forsAddr){
        int[] indices = new int[SPX_FORS_TREES];
        byte[] roots = new byte[SPX_FORS_TREES*SPX_N];
        byte[] leaf = new byte[SPX_N];
        int[] forsTreeAddr = new int[8];
        int[] forsPkAddr = new int[8];
        int idxOffset;

        copyKeypairAddr(forsTreeAddr, forsAddr);
        copyKeypairAddr(forsPkAddr, forsAddr);

        setByte(forsTreeAddr, SPX_OFFSET_TYPE, (byte) SPX_ADDR_TYPE_FORSTREE);
        setByte(forsPkAddr, SPX_OFFSET_TYPE, (byte) SPX_ADDR_TYPE_FORSPK);

        messageToIndices(indices, m);

        for(int i = 0; i < SPX_FORS_TREES; i++){
            idxOffset = i*(1 << SPX_FORS_HEIGHT);

            setTreeHeight(forsTreeAddr, 0);
            setTreeIndex(forsTreeAddr, indices[i]+idxOffset);

            thash(leaf, 0, sig, sigOffset, 1, ctx, forsTreeAddr);
            sigOffset += SPX_N;

            computeRoot(roots, i*SPX_N, leaf, indices[i], idxOffset, sig, sigOffset, SPX_FORS_HEIGHT, ctx, forsTreeAddr);
            sigOffset += SPX_N*SPX_FORS_HEIGHT;
        }

        thash(pk, 0, roots, 0, SPX_FORS_TREES, ctx, forsPkAddr);
    }

    private void wotsPkFromSig(byte[] pk, byte[] sig, int sigOffset, byte[] msg, SphincsCtx ctx, int[] addr){
        int[] lengths = new int[SPX_WOTS_LEN];

        chainLengths(lengths, msg, 0);

        for(int i = 0; i < SPX_WOTS_LEN; i++){
            setByte(addr, SPX_OFFSET_CHAIN_ADDR, (byte) i);
            genChain(pk, i*SPX_N, sig, sigOffset+i*SPX_N, lengths[i], SPX_WOTS_W-1-lengths[i], ctx, addr);
        }
    }

    private void computeRoot(byte[] root, int rootOffset, byte[] leaf, int leafIdx, int idxOffset, byte[] authPath, int authPathIndex, int treeHeight, SphincsCtx ctx, int[] addr){
        byte[] buffer = new byte[2*SPX_N];

        if((leafIdx & 1) != 0){
            System.arraycopy(leaf, 0, buffer, SPX_N, SPX_N);
            System.arraycopy(authPath, authPathIndex, buffer, 0, SPX_N);
        }else{
            System.arraycopy(leaf, 0, buffer, 0, SPX_N);
            System.arraycopy(authPath, authPathIndex, buffer, SPX_N, SPX_N);
        }

        authPathIndex += SPX_N;

        for(int i = 0; i < treeHeight-1; i++){
            leafIdx >>= 1;
            idxOffset >>= 1;
            setTreeHeight(addr, i+1);
            setTreeIndex(addr, leafIdx+idxOffset);

            if((leafIdx & 1) != 0){
                thash(buffer, SPX_N, buffer, 0, 2, ctx, addr);
                System.arraycopy(authPath, authPathIndex, buffer, 0, SPX_N);
            }else{
                thash(buffer, 0, buffer, 0, 2, ctx, addr);
                System.arraycopy(authPath, authPathIndex, buffer, SPX_N, SPX_N);
            }

            authPathIndex += SPX_N;
        }

        leafIdx >>= 1;
        idxOffset >>= 1;
        setTreeHeight(addr, treeHeight);
        setTreeIndex(addr, leafIdx+idxOffset);
        thash(root, rootOffset, buffer, 0, 2, ctx, addr);
    }

    private void genChain(byte[] out, int outOffset, byte[] in, int inOffset, int start, int steps, SphincsCtx ctx, int[] addr){
        System.arraycopy(in, inOffset, out, outOffset, SPX_N);

        for(int i = start; i < (start+steps) && i < SPX_WOTS_W; i++){
            setByte(addr, SPX_OFFSET_HASH_ADDR, (byte) i);
            thash(out, outOffset, out, outOffset, 1, ctx, addr);
        }
    }

    private static void setByte(int[] out, int byteOffset, byte val){
        int index = byteOffset/4;
        int mod = byteOffset%4;
        int prior = out[index];
        out[index] = (prior & ~(0xFF << (mod*8))) | ((val & 0xFF) << (mod*8));
    }

    private static byte getByte(int[] in, int byteOffset){
        int index = byteOffset/4;
        int mod = byteOffset%4;
        return (byte) (in[index] >> (mod*8));
    }

    private static void setKeyPairAddr(int[] addr, int keypair){
        if(SPX_FULL_HEIGHT/SPX_D > 8){
            setByte(addr, SPX_OFFSET_KP_ADDR2, (byte) (keypair >> 8));
        }
        setByte(addr, SPX_OFFSET_KP_ADDR1, (byte) keypair);
    }

    private static void setLayerAddr(int[] addr, int layer){
        if(SPX_OFFSET_LAYER == 0){
            addr[0] = layer;
            return;
        }

        throw new IllegalStateException("Unimplemented bit munging!");
    }

    private static void copySubtreeAddr(int[] out, int[] in){
        System.arraycopy(in, 0, out, 0, 2);
        setByte(out, 8+SPX_OFFSET_TREE-1, getByte(in, 8+SPX_OFFSET_TREE-1));
    }

    private static void merkleSign(byte[] sig, int sigOffset, byte[] root, int rootOffset, SphincsCtx ctx, int[] wotsAddr, int[] treeAddr, int idxLeaf){
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

        treeHashx1(root, rootOffset, sig, sigOffset+SPX_WOTS_BYTES, ctx, idxLeaf, 0, SPX_TREE_HEIGHT, (a, b, c, d) -> wotsGenLeafx1(a, b, c, d, info), treeAddr);
    }

    private static void mgf1_256(byte[] out, int outIndex, int outlen, byte[] in, int inlen){
        byte[] inbuf = new byte[inlen+4];
        byte[] outbuf = new byte[SPX_SHA256_OUTPUT_BYTES];
        int i;

        System.arraycopy(in, 0, inbuf, 0, inlen);

        for(i = 0; (i+1)*SPX_SHA256_OUTPUT_BYTES <= outlen; i++){
            u32ToBytes(inbuf, inlen, i);

            MessageDigest md = sha2.get();
            md.update(inbuf);
            byte[] res = md.digest();
            System.arraycopy(res, 0, out, outIndex, res.length);

            outIndex += SPX_SHA256_OUTPUT_BYTES;
        }

        if(outlen > i*SPX_SHA256_OUTPUT_BYTES){
            u32ToBytes(inbuf, inlen, i);

            MessageDigest md = sha2.get();
            md.update(inbuf);
            byte[] res = md.digest();
            System.arraycopy(res, 0, outbuf, 0, res.length);

            System.arraycopy(outbuf, 0, out, outIndex, outlen-i*SPX_SHA256_OUTPUT_BYTES);
        }
    }

    private static void setTreeHeight(int[] addr, int treeHeight){
        setByte(addr, SPX_OFFSET_TREE_HGT, (byte) treeHeight);
    }

    private static void setTreeIndex(int[] addr, int treeIndex){
        setByte(addr, SPX_OFFSET_TREE_INDEX+3, (byte) treeIndex);
        setByte(addr, SPX_OFFSET_TREE_INDEX+2, (byte) (treeIndex >> 8));
        setByte(addr, SPX_OFFSET_TREE_INDEX+1, (byte) (treeIndex >> 16));
        setByte(addr, SPX_OFFSET_TREE_INDEX+0, (byte) (treeIndex >> 24));
    }

    private static void prfAddr(byte[] out, int outOffset, SphincsCtx ctx, int[] addr){
        byte[] sha2State = new byte[40];
        byte[] buf = new byte[SPX_SHA256_ADDR_BYTES+SPX_N];

        System.arraycopy(ctx.getStateSeeded(), 0, sha2State, 0, 40);

        System.arraycopy(intsToBytes(addr, SPX_SHA256_ADDR_BYTES), 0, buf, 0, SPX_SHA256_ADDR_BYTES);
        System.arraycopy(ctx.getSkSeed(), 0, buf, SPX_SHA256_ADDR_BYTES, SPX_N);

        SHA256 res = new SHA256(sha2State, 64);
        res.update(buf);
        byte[] state = res.digest();

        System.arraycopy(state, 0, out, outOffset, SPX_N);
    }

    private static void treeHashx1(byte[] root, int rootOffset, byte[] authPath, int auth_pathOffset, SphincsCtx ctx, int leafIdx, int idxOffset, int treeHeight, GenLeaf genLeaf, int[] treeAddr){
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

    private static void thash(byte[] out, int outOffset, byte[] in, int inOffset, int inblocks, SphincsCtx ctx, int[] addr){
        byte[] buf = new byte[SPX_N+SPX_SHA256_ADDR_BYTES+inblocks*SPX_N];
        byte[] bitmask = new byte[inblocks*SPX_N];
        byte[] sha2State = new byte[40];

        System.arraycopy(ctx.getPubSeed(), 0, buf, 0, SPX_N);
        System.arraycopy(intsToBytes(addr, SPX_SHA256_ADDR_BYTES), 0, buf, SPX_N, SPX_SHA256_ADDR_BYTES);
        mgf1_256(bitmask, 0, inblocks*SPX_N, buf, SPX_N+SPX_SHA256_ADDR_BYTES);

        System.arraycopy(ctx.getStateSeeded(), 0, sha2State, 0, 40);

        for(int i = 0; i < inblocks*SPX_N; i++){
            buf[SPX_N+SPX_SHA256_ADDR_BYTES+i] = (byte)(in[inOffset+i] ^ bitmask[i]);
        }

        SHA256 res = new SHA256(sha2State, 64);
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

    private void forsGenLeafx1(byte[] leaf, int leafOffset, SphincsCtx ctx, int addrIdx, ForsGenLeafInfo info){
        int[] forsLeafAddr = info.getLeafAddrX();

        setTreeIndex(forsLeafAddr, addrIdx);
        setByte(forsLeafAddr, SPX_OFFSET_TYPE, (byte) SPX_ADDR_TYPE_FORSPRF);
        prfAddr(leaf, leafOffset, ctx, forsLeafAddr);

        setByte(forsLeafAddr, SPX_OFFSET_TYPE, (byte) SPX_ADDR_TYPE_FORSTREE);
        thash(leaf, leafOffset, leaf, leafOffset, 1, ctx, forsLeafAddr);
    }

    private static void chainLengths(int[] lengths, byte[] msg, int offset){
        baseW(lengths, 0, SPX_WOTS_LEN1, msg, offset);
        wotsChecksum(lengths, SPX_WOTS_LEN1);
    }

    private static void baseW(int[] output, int outputOffset, int out_len,  byte[] input, int inputOffset){
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

    private static void u32ToBytes(byte[] out, int outOffset, int in){
        out[outOffset+0] = (byte)(in >> 24);
        out[outOffset+1] = (byte)(in >> 16);
        out[outOffset+2] = (byte)(in >> 8);
        out[outOffset+3] = (byte)in;
    }

    private static void wotsGenLeafx1(byte[] dest, int destOffset, SphincsCtx ctx, int leafIdx, LeafInfoX1 vInfo){
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

    private static void wotsChecksum(int[] csumBaseW, int offset){
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

    private static void ullToBytes(byte[] out, int in){
        for(int i = out.length-1; i >= 0; i--){
            out[i] = (byte)in;
            in = in >> 8;
        }
    }

    private static MessageDigest getInstance(){
        try{
            return MessageDigest.getInstance("SHA-256");

        }catch(NoSuchAlgorithmException e){
            throw new RuntimeException(e);
        }
    }
}
