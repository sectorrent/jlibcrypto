package org.sectorrent.jlibcrypto.kyber.utils;

import org.sectorrent.jlibcrypto.kyber.KyberParams;

import java.util.Arrays;

public class ByteUtils {

    /**
     * Returns a 32-bit unsigned integer as a long from byte x
     *
     * @param x
     * @return
     */
    public static long convertByteTo32BitUnsignedInt(byte[] x) {
        long r = (long) (x[0] & 0xFF);
        r = r | (long) ((long) (x[1] & 0xFF) << 8);
        r = r | (long) ((long) (x[2] & 0xFF) << 16);
        r = r | (long) ((long) (x[3] & 0xFF) << 24);
        return r;
    }

    /**
     * Returns a 24-bit unsigned integer as a long from byte x
     *
     * @param x
     * @return
     */
    public static long convertByteTo24BitUnsignedInt(byte[] x) {
        long r = (long) (x[0] & 0xFF);
        r = r | (long) ((long) (x[1] & 0xFF) << 8);
        r = r | (long) ((long) (x[2] & 0xFF) << 16);
        return r;
    }

    /**
     * Generate a polynomial with coefficients distributed according to a
     * centered binomial distribution with parameter eta, given an array of
     * uniformly random bytes.
     *
     * @param buf
     * @param paramsK
     * @return
     */
    public static short[] generateCBDPoly(byte[] buf, int paramsK) {
        long t, d; //both unsigned
        int a, b;
        short[] r = new short[KyberParams.PARAMS_POLY_BYTES];
        switch (paramsK) {
            case 2:
                for (int i = 0; i < KyberParams.PARAMS_N / 4; i++) {
                    t = ByteUtils.convertByteTo24BitUnsignedInt(Arrays.copyOfRange(buf, (3 * i), buf.length));
                    d = t & 0x00249249;
                    d = d + ((t >> 1) & 0x00249249);
                    d = d + ((t >> 2) & 0x00249249);
                    for (int j = 0; j < 4; j++) {
                        a = (short) ((d >> (6 * j + 0)) & 0x7);
                        b = (short) ((d >> (6 * j + KyberParams.PARAMS_ETAK512)) & 0x7);
                        r[4 * i + j] = (short) (a - b);
                    }
                }
                break;
            default:
                for (int i = 0; i < KyberParams.PARAMS_N / 8; i++) {
                    t = ByteUtils.convertByteTo32BitUnsignedInt(Arrays.copyOfRange(buf, (4 * i), buf.length));
                    d = t & 0x55555555;
                    d = d + ((t >> 1) & 0x55555555);
                    for (int j = 0; j < 8; j++) {
                        a = (short) ((d >> (4 * j + 0)) & 0x3);
                        b = (short) ((d >> (4 * j + KyberParams.PARAMS_ETAK768_K1024)) & 0x3);
                        r[8 * i + j] = (short) (a - b);
                    }
                }
        }
        return r;
    }

    /**
     * Computes a Montgomery reduction given a 32 Bit Integer
     *
     * @param a
     * @return
     */
    public static short montgomeryReduce(long a) {
        short u = (short) (a * KyberParams.PARAMS_QINV);
        int t = (int) (u * KyberParams.PARAMS_Q);
        t = (int) (a - t);
        t >>= 16;
        return (short) t;
    }

    /**
     * Computes a Barrett reduction given a 16 Bit Integer
     *
     * @param a
     * @return
     */
    public static short barrettReduce(short a) {
        short t;
        long shift = (((long) 1) << 26);
        short v = (short) ((shift + (KyberParams.PARAMS_Q / 2)) / KyberParams.PARAMS_Q);
        t = (short) ((v * a) >> 26);
        t = (short) (t * KyberParams.PARAMS_Q);
        return (short) (a - t);
    }

    /**
     * Conditionally subtract Q (from KyberParams) from a
     *
     * @param a
     * @return
     */
    public static short conditionalSubQ(short a) {
        a = (short) (a - KyberParams.PARAMS_Q);
        a = (short) (a + ((int) ((int) a >> 15) & KyberParams.PARAMS_Q));
        return a;
    }
}
