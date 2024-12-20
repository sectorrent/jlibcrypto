package org.sectorrent.jlibcrypto.sphincs.utils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.ForkJoinTask;

import static org.sectorrent.jlibcrypto.sphincs.SphincsPlusParams.*;

public class Wots {

    public static void wotsGenLeafx1(byte[] dest, int destOffset, SphincsCtx ctx, int leafIdx, LeafInfoX1 vInfo){
        //LeafInfoX1 info = vInfo;
        int[] leafAddr = vInfo.getLeafAddress();

        int[] pkAddr = vInfo.getPkAddress();
        byte[] pkBuffer = new byte[SPX_WOTS_BYTES];
        int wotsKMask;

        if(leafIdx == vInfo.getWotsSignLeaf()){
            wotsKMask = 0;

        }else{
            wotsKMask = ~0;
        }

        AddressUtils.setKeyPairAddress(leafAddr, leafIdx);
        AddressUtils.setKeyPairAddress(pkAddr, leafIdx);

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
                wotsLoops(splits.get(jCopy), splits.get(jCopy+1), pkBuffer, splits.get(jCopy)*SPX_N, wotsKMask, addrs, vInfo, ctx);

            }else{
                ForkJoinTask<Boolean> task = ForkJoinPool.commonPool().submit(() -> wotsLoops(splits.get(jCopy), splits.get(jCopy+1), pkBuffer, splits.get(jCopy)*SPX_N, wotsKMask, addrs, vInfo, ctx));
                thashes.add(task);
            }
        }

        for(ForkJoinTask<Boolean> hash : thashes){
            hash.join();
        }

        TreeHash.treeHash(dest, destOffset, pkBuffer, 0, SPX_WOTS_LEN, ctx, pkAddr);
    }

    public static boolean wotsLoops(int start, int end, byte[] buffer, int bufferOffset, int wotsKMask, int[] leafAddr, LeafInfoX1 info, SphincsCtx ctx){
        int[] wotsSteps = info.getWotsSteps();

        for(int i = start; i < end; i++, bufferOffset += SPX_N){
            int wotsK = wotsSteps[i] | wotsKMask;

            ByteUtils.setByte(leafAddr, SPX_OFFSET_CHAIN_ADDR, (byte) i);
            ByteUtils.setByte(leafAddr, SPX_OFFSET_HASH_ADDR, (byte) 0);
            ByteUtils.setByte(leafAddr, SPX_OFFSET_TYPE, (byte) SPX_ADDR_TYPE_WOTSPRF);

            AddressUtils.prfAddress(buffer, bufferOffset, ctx, leafAddr);

            ByteUtils.setByte(leafAddr, SPX_OFFSET_TYPE, (byte) SPX_ADDR_TYPE_WOTS);

            wotsComponent(buffer, bufferOffset, leafAddr, i, wotsK, info, ctx);
        }

        return true;
    }

    public static boolean wotsComponent(byte[] buffer, int off, int[] addrs, int i, int wotsK, LeafInfoX1 info, SphincsCtx ctx){
        for(int k = 0;; k++){
            if(k == wotsK){
                System.arraycopy(buffer, off, info.getWotsSig(), info.getWotsSigOffset()+i*SPX_N, SPX_N);
            }

            if(k == SPX_WOTS_W-1){
                break;
            }

            ByteUtils.setByte(addrs, SPX_OFFSET_HASH_ADDR, (byte) k);
            TreeHash.treeHash(buffer, off, buffer, off, 1, ctx, addrs);
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
        ByteUtils.ullToBytes(csumBytes, csum);
        baseW(csumBaseW, offset, SPX_WOTS_LEN2, csumBytes, 0);
    }

    public static void wotsPkFromSig(byte[] pk, byte[] sig, int sigOffset, byte[] msg, SphincsCtx ctx, int[] addr){
        int[] lengths = new int[SPX_WOTS_LEN];

        chainLengths(lengths, msg, 0);

        for(int i = 0; i < SPX_WOTS_LEN; i++){
            ByteUtils.setByte(addr, SPX_OFFSET_CHAIN_ADDR, (byte) i);
            genChain(pk, i*SPX_N, sig, sigOffset+i*SPX_N, lengths[i], SPX_WOTS_W-1-lengths[i], ctx, addr);
        }
    }

    private static void baseW(int[] output, int outputOffset, int outLen,  byte[] input, int inputOffset){
        int in = 0;
        int out = 0;
        int total = 0;
        int bits = 0;
        int consumed;

        for(consumed = 0; consumed < outLen; consumed++){
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

    public static void chainLengths(int[] lengths, byte[] msg, int offset){
        baseW(lengths, 0, SPX_WOTS_LEN1, msg, offset);
        Wots.wotsChecksum(lengths, SPX_WOTS_LEN1);
    }

    private static void genChain(byte[] out, int outOffset, byte[] in, int inOffset, int start, int steps, SphincsCtx ctx, int[] addr){
        System.arraycopy(in, inOffset, out, outOffset, SPX_N);

        for(int i = start; i < (start+steps) && i < SPX_WOTS_W; i++){
            ByteUtils.setByte(addr, SPX_OFFSET_HASH_ADDR, (byte) i);
            TreeHash.treeHash(out, outOffset, out, outOffset, 1, ctx, addr);
        }
    }
}
