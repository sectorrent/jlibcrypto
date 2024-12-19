package org.sectorrent.jlibcrypto.sphincs;

import static org.sectorrent.jlibcrypto.sphincs.Sphincs.SPX_N;

public class SphincsCtx {

    byte[] pubSeed = new byte[SPX_N];
    byte[] skSeed = new byte[SPX_N];
    byte[] stateSeeded;
}
