package org.sectorrent.jlibcrypto.sphincs;

public interface GenLeaf {

    void apply(byte[] dest, int destOffset, SphincsCtx ctx, int leaf_idx);
}
