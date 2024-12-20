package org.sectorrent.jlibcrypto.sphincs.utils;

import org.sectorrent.jlibcrypto.hash.SHA256;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static org.sectorrent.jlibcrypto.sphincs.SphincsPlusParams.*;
import static org.sectorrent.jlibcrypto.sphincs.SphincsPlusParams.SPX_OFFSET_TREE_INDEX;

public class TreeHash {

    public static final ThreadLocal<MessageDigest> sha2 = ThreadLocal.withInitial(() -> getInstance());

    public static void treeHashX1(byte[] root, int rootOffset, byte[] authPath, int auth_pathOffset, SphincsCtx ctx, int leafIdx, int idxOffset, int treeHeight, GenLeaf genLeaf, int[] treeAddr){
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
                treeHash(current, 1*SPX_N, current, 0, 2, ctx, treeAddr);
            }

            System.arraycopy(current, SPX_N, stack, h*SPX_N, SPX_N);
        }
    }

    public static void treeHash(byte[] out, int outOffset, byte[] in, int inOffset, int inblocks, SphincsCtx ctx, int[] addr){
        byte[] buf = new byte[SPX_N+SPX_SHA256_ADDR_BYTES+inblocks*SPX_N];
        byte[] bitmask = new byte[inblocks*SPX_N];
        byte[] sha2State = new byte[40];

        System.arraycopy(ctx.getPubSeed(), 0, buf, 0, SPX_N);
        System.arraycopy(ByteUtils.intsToBytes(addr, SPX_SHA256_ADDR_BYTES), 0, buf, SPX_N, SPX_SHA256_ADDR_BYTES);
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

    public static void setTreeIndex(int[] addr, int treeIndex){
        ByteUtils.setByte(addr, SPX_OFFSET_TREE_INDEX+3, (byte) treeIndex);
        ByteUtils.setByte(addr, SPX_OFFSET_TREE_INDEX+2, (byte) (treeIndex >> 8));
        ByteUtils.setByte(addr, SPX_OFFSET_TREE_INDEX+1, (byte) (treeIndex >> 16));
        ByteUtils.setByte(addr, SPX_OFFSET_TREE_INDEX+0, (byte) (treeIndex >> 24));
    }

    public static void setTreeHeight(int[] addr, int treeHeight){
        ByteUtils.setByte(addr, SPX_OFFSET_TREE_HGT, (byte) treeHeight);
    }

    public static void setTreeAddress(int[] addr, long tree){
        if((SPX_TREE_HEIGHT*(SPX_D-1)) > 64){
            throw new IllegalStateException("Subtree addressing is currently limited to at most 2^64 trees");
        }

        for(int i = 0; i < 8; i++){
            ByteUtils.setByte(addr, SPX_OFFSET_TREE+i, (byte) (tree >> (56-8*i)));
        }
    }

    public static void mgf1_256(byte[] out, int outIndex, int outlen, byte[] in, int inlen){
        byte[] inbuf = new byte[inlen+4];
        byte[] outbuf = new byte[SPX_SHA256_OUTPUT_BYTES];
        int i;

        System.arraycopy(in, 0, inbuf, 0, inlen);

        for(i = 0; (i+1)*SPX_SHA256_OUTPUT_BYTES <= outlen; i++){
            ByteUtils.u32ToBytes(inbuf, inlen, i);

            MessageDigest md = sha2.get();
            md.update(inbuf);
            byte[] res = md.digest();
            System.arraycopy(res, 0, out, outIndex, res.length);

            outIndex += SPX_SHA256_OUTPUT_BYTES;
        }

        if(outlen > i*SPX_SHA256_OUTPUT_BYTES){
            ByteUtils.u32ToBytes(inbuf, inlen, i);

            MessageDigest md = sha2.get();
            md.update(inbuf);
            byte[] res = md.digest();
            System.arraycopy(res, 0, outbuf, 0, res.length);

            System.arraycopy(outbuf, 0, out, outIndex, outlen-i*SPX_SHA256_OUTPUT_BYTES);
        }
    }

    public static MessageDigest getInstance(){
        try{
            return MessageDigest.getInstance("SHA-256");

        }catch(NoSuchAlgorithmException e){
            throw new RuntimeException(e);
        }
    }
}
