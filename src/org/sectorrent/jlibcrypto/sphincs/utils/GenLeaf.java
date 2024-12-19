package org.sectorrent.jlibcrypto.sphincs.utils;

public interface GenLeaf {

    void apply(byte[] dest, int destOffset, SphincsCtx ctx, int leaf_idx);
}
