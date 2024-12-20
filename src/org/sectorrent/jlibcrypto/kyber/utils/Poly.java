package org.sectorrent.jlibcrypto.kyber.utils;

import org.sectorrent.jlibcrypto.kyber.KyberParams;

public class Poly {

    /*
    public static short[] getNoisePoly(byte[] seed, byte nonce, int paramsK) {
        int l;
        byte[] p;
        switch (paramsK) {
            case 2:
                l = KyberParams.paramsETAK512 * KyberParams.paramsN / 4;
                break;
            default:
                l = KyberParams.paramsETAK768K1024 * KyberParams.paramsN / 4;
        }

        p = Indcpa.generatePRFByteArray(l, seed, nonce);
        return ByteOps.generateCBDPoly(p, paramsK);
    }
    */

    public static short[][] generateNewPolyVector(int paramsK){
        return new short[paramsK][KyberParams.PARAMS_POLY_BYTES];
    }
}
