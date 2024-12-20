package org.sectorrent.jlibcrypto.sphincs.utils;

import org.sectorrent.jlibcrypto.hash.SHA256;

import static org.sectorrent.jlibcrypto.sphincs.SphincsPlusParams.*;
import static org.sectorrent.jlibcrypto.sphincs.SphincsPlusParams.SPX_N;

public class AddressUtils {

    public static void setKeyPairAddress(int[] addr, int keypair){
        if(SPX_FULL_HEIGHT/SPX_D > 8){
            ByteUtils.setByte(addr, SPX_OFFSET_KP_ADDR2, (byte) (keypair >> 8));
        }

        ByteUtils.setByte(addr, SPX_OFFSET_KP_ADDR1, (byte) keypair);
    }

    public static void setLayerAddress(int[] addr, int layer){
        if(SPX_OFFSET_LAYER == 0){
            addr[0] = layer;
            return;
        }

        throw new IllegalStateException("Unimplemented bit munging!");
    }

    public static void copySubTreeAddress(int[] out, int[] in){
        System.arraycopy(in, 0, out, 0, 2);
        ByteUtils.setByte(out, 8+SPX_OFFSET_TREE-1, ByteUtils.getByte(in, 8+SPX_OFFSET_TREE-1));
    }

    public static void copyKeypairAddress(int[] out, int[] in){
        out[0] = in[0];
        out[1] = in[1];
        ByteUtils.setByte(out, SPX_OFFSET_TREE+8-1, ByteUtils.getByte(in, SPX_OFFSET_TREE+8-1));

        if(SPX_FULL_HEIGHT/SPX_D > 8){
            ByteUtils.setByte(out, SPX_OFFSET_KP_ADDR2, ByteUtils.getByte(in, SPX_OFFSET_KP_ADDR2));
        }

        ByteUtils.setByte(out, SPX_OFFSET_KP_ADDR1, ByteUtils.getByte(in, SPX_OFFSET_KP_ADDR1));
    }

    public static void prfAddress(byte[] out, int outOffset, SphincsCtx ctx, int[] addr){
        byte[] sha2State = new byte[40];
        byte[] buf = new byte[SPX_SHA256_ADDR_BYTES+SPX_N];

        System.arraycopy(ctx.getStateSeeded(), 0, sha2State, 0, 40);

        System.arraycopy(ByteUtils.intsToBytes(addr, SPX_SHA256_ADDR_BYTES), 0, buf, 0, SPX_SHA256_ADDR_BYTES);
        System.arraycopy(ctx.getSkSeed(), 0, buf, SPX_SHA256_ADDR_BYTES, SPX_N);

        SHA256 res = new SHA256(sha2State, 64);
        res.update(buf);
        byte[] state = res.digest();

        System.arraycopy(state, 0, out, outOffset, SPX_N);
    }
}
