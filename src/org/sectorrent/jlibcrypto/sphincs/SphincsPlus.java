package org.sectorrent.jlibcrypto.sphincs;

import org.sectorrent.jlibcrypto.sphincs.utils.*;

import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static org.sectorrent.jlibcrypto.sphincs.SphincsPlusParams.*;

public class SphincsPlus {

    private byte[] key;
    private byte[] message;

    public SphincsPlus(byte[] key){
        this.key = key;
    }

    public byte[] sign(){
        byte[] sig = new byte[SPX_BYTES+message.length];
        SphincsCtx ctx = new SphincsCtx();
        byte[] skPrf = Arrays.copyOfRange(key, SPX_N, key.length);
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

        ByteUtils.setByte(wotsAddr, SPX_OFFSET_TYPE, (byte) SPX_ADDR_TYPE_WOTS);
        ByteUtils.setByte(treeAddr, SPX_OFFSET_TYPE, (byte) SPX_ADDR_TYPE_HASHTREE);

        genMessageRandom(sig, skPrf, optrand, message);

        hashMessage(mhash, tree, idxLeaf, sig, pk, message);
        int sigOffset = SPX_N;

        TreeHash.setTreeAddress(wotsAddr, tree[0]);
        AddressUtils.setKeyPairAddress(wotsAddr, idxLeaf[0]);

        forsSign(sig, sigOffset, root, mhash, ctx, wotsAddr);
        sigOffset += SPX_FORS_BYTES;

        for(int i = 0; i < SPX_D; i++){
            AddressUtils.setLayerAddress(treeAddr, i);
            TreeHash.setTreeAddress(treeAddr, tree[0]);

            AddressUtils.copySubTreeAddress(wotsAddr, treeAddr);
            AddressUtils.setKeyPairAddress(wotsAddr, idxLeaf[0]);

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

        ByteUtils.setByte(wotsAddr, SPX_OFFSET_TYPE, (byte) SPX_ADDR_TYPE_WOTS);
        ByteUtils.setByte(treeAddr, SPX_OFFSET_TYPE, (byte) SPX_ADDR_TYPE_HASHTREE);
        ByteUtils.setByte(wotsPkAddr, SPX_OFFSET_TYPE, (byte) SPX_ADDR_TYPE_WOTSPK);

        hashMessage(mhash, tree, idxLeaf, sig, key, m);
        sigOffset += SPX_N;

        TreeHash.setTreeAddress(wotsAddr, tree[0]);
        AddressUtils.setKeyPairAddress(wotsAddr, idxLeaf[0]);

        forsPkFromSig(root, sig, sigOffset, mhash, ctx, wotsAddr);
        sigOffset += SPX_FORS_BYTES;

        for(int i = 0; i < SPX_D; i++){
            AddressUtils.setLayerAddress(treeAddr, i);
            TreeHash.setTreeAddress(treeAddr, tree[0]);

            AddressUtils.copySubTreeAddress(wotsAddr, treeAddr);
            AddressUtils.setKeyPairAddress(wotsAddr, idxLeaf[0]);

            AddressUtils.copyKeypairAddress(wotsPkAddr, wotsAddr);

            Wots.wotsPkFromSig(wotsPk, sig, sigOffset, root, ctx, wotsAddr);
            sigOffset += SPX_WOTS_BYTES;

            TreeHash.treeHash(leaf, 0, wotsPk, 0, SPX_WOTS_LEN, ctx, wotsPkAddr);

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

        AddressUtils.setLayerAddress(topTreeAddr, SPX_D-1);
        AddressUtils.setLayerAddress(wotsAddr, SPX_D-1);

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

        MessageDigest hash = TreeHash.getInstance();
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

        MessageDigest md = TreeHash.sha2.get();
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

            MessageDigest md = TreeHash.sha2.get();
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

        TreeHash.mgf1_256(buf, bufp, SPX_DGST_BYTES, seed, 2*SPX_N+SPX_SHAX_OUTPUT_BYTES);

        System.arraycopy(buf, bufp, digest, 0, SPX_FORS_MSG_BYTES);
        bufp += SPX_FORS_MSG_BYTES;

        if(SPX_TREE_BITS > 64){
            throw new IllegalStateException("For given height and depth, 64 bits cannot represent all subtrees");
        }

        tree[0] = ByteUtils.bytesToUll(buf, bufp, SPX_TREE_BYTES);
        tree[0] &= ((1L << SPX_TREE_BITS)-1);
        bufp += SPX_TREE_BYTES;

        leafIdx[0] = (int) ByteUtils.bytesToUll(buf, bufp, SPX_LEAF_BYTES);
        leafIdx[0] &= ((1 << SPX_LEAF_BITS)-1);
    }

    private void forsSign(byte[] sig, int sigOffset, byte[] pk, byte[] m, SphincsCtx ctx, int[] forsAddr){
        int[] indices = new int[SPX_FORS_TREES];
        byte[] roots = new byte[SPX_FORS_TREES*SPX_N];
        int[] forsTreeAddr = new int[8];
        ForsGenLeafInfo forsInfo = new ForsGenLeafInfo();
        int[] forsLeafAddr = forsInfo.getLeafAddressX();
        int[] forsPkAddr = new int[8];
        int idxOffset;

        AddressUtils.copyKeypairAddress(forsTreeAddr, forsAddr);
        AddressUtils.copyKeypairAddress(forsLeafAddr, forsAddr);
        AddressUtils.copyKeypairAddress(forsPkAddr, forsAddr);

        ByteUtils.setByte(forsPkAddr, SPX_OFFSET_TYPE, (byte) SPX_ADDR_TYPE_FORSPK);

        messageToIndices(indices, m);

        for(int i = 0; i < SPX_FORS_TREES; i++){
            idxOffset = i*(1 << SPX_FORS_HEIGHT);

            TreeHash.setTreeHeight(forsTreeAddr, 0);
            TreeHash.setTreeIndex(forsTreeAddr, indices[i]+idxOffset);
            ByteUtils.setByte(forsTreeAddr, SPX_OFFSET_TYPE, (byte) SPX_ADDR_TYPE_FORSPRF);

            AddressUtils.prfAddress(sig, sigOffset, ctx, forsTreeAddr);
            ByteUtils.setByte(forsTreeAddr, SPX_OFFSET_TYPE, (byte) SPX_ADDR_TYPE_FORSTREE);
            sigOffset += SPX_N;

            TreeHash.treeHashX1(roots, i*SPX_N, sig, sigOffset, ctx, indices[i], idxOffset, SPX_FORS_HEIGHT, (a, b, c, d) -> forsGenLeafx1(a, b, c, d, forsInfo), forsTreeAddr);

            sigOffset += SPX_N*SPX_FORS_HEIGHT;
        }

        TreeHash.treeHash(pk, 0, roots, 0, SPX_FORS_TREES, ctx, forsPkAddr);
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

        AddressUtils.copyKeypairAddress(forsTreeAddr, forsAddr);
        AddressUtils.copyKeypairAddress(forsPkAddr, forsAddr);

        ByteUtils.setByte(forsTreeAddr, SPX_OFFSET_TYPE, (byte) SPX_ADDR_TYPE_FORSTREE);
        ByteUtils.setByte(forsPkAddr, SPX_OFFSET_TYPE, (byte) SPX_ADDR_TYPE_FORSPK);

        messageToIndices(indices, m);

        for(int i = 0; i < SPX_FORS_TREES; i++){
            idxOffset = i*(1 << SPX_FORS_HEIGHT);

            TreeHash.setTreeHeight(forsTreeAddr, 0);
            TreeHash.setTreeIndex(forsTreeAddr, indices[i]+idxOffset);

            TreeHash.treeHash(leaf, 0, sig, sigOffset, 1, ctx, forsTreeAddr);
            sigOffset += SPX_N;

            computeRoot(roots, i*SPX_N, leaf, indices[i], idxOffset, sig, sigOffset, SPX_FORS_HEIGHT, ctx, forsTreeAddr);
            sigOffset += SPX_N*SPX_FORS_HEIGHT;
        }

        TreeHash.treeHash(pk, 0, roots, 0, SPX_FORS_TREES, ctx, forsPkAddr);
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
            TreeHash.setTreeHeight(addr, i+1);
            TreeHash.setTreeIndex(addr, leafIdx+idxOffset);

            if((leafIdx & 1) != 0){
                TreeHash.treeHash(buffer, SPX_N, buffer, 0, 2, ctx, addr);
                System.arraycopy(authPath, authPathIndex, buffer, 0, SPX_N);
            }else{
                TreeHash.treeHash(buffer, 0, buffer, 0, 2, ctx, addr);
                System.arraycopy(authPath, authPathIndex, buffer, SPX_N, SPX_N);
            }

            authPathIndex += SPX_N;
        }

        leafIdx >>= 1;
        idxOffset >>= 1;
        TreeHash.setTreeHeight(addr, treeHeight);
        TreeHash.setTreeIndex(addr, leafIdx+idxOffset);
        TreeHash.treeHash(root, rootOffset, buffer, 0, 2, ctx, addr);
    }

    private static void merkleSign(byte[] sig, int sigOffset, byte[] root, int rootOffset, SphincsCtx ctx, int[] wotsAddr, int[] treeAddr, int idxLeaf){
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

    private void forsGenLeafx1(byte[] leaf, int leafOffset, SphincsCtx ctx, int addrIdx, ForsGenLeafInfo info){
        int[] forsLeafAddr = info.getLeafAddressX();

        TreeHash.setTreeIndex(forsLeafAddr, addrIdx);
        ByteUtils.setByte(forsLeafAddr, SPX_OFFSET_TYPE, (byte) SPX_ADDR_TYPE_FORSPRF);
        AddressUtils.prfAddress(leaf, leafOffset, ctx, forsLeafAddr);

        ByteUtils.setByte(forsLeafAddr, SPX_OFFSET_TYPE, (byte) SPX_ADDR_TYPE_FORSTREE);
        TreeHash.treeHash(leaf, leafOffset, leaf, leafOffset, 1, ctx, forsLeafAddr);
    }
}
