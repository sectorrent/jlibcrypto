package org.sectorrent.jlibcrypto.sphincs;

public class LeafInfoX1 {

    byte[] wotsSig;
    int wotsSigOffset=0;
    int wotsSignLeaf; /* The index of the WOTS we're using to sign */
    int[] wotsSteps;
    int[] leafAddr = new int[8];
    int[] pkAddr = new int[8];
}
