package org.sectorrent.jlibcrypto.kyber.utils;

import org.sectorrent.jlibcrypto.kyber.KyberParams;

import java.util.Arrays;

public class Poly {

    protected short[] poly = new short[KyberParams.PARAMS_POLY_BYTES];
    protected short[][] polyvec;

    /**
     * Performs lossy compression and serialization of a polynomial
     *
     * @param polyA
     * @param paramsK
     * @return
     */
    public static byte[] compressPoly(short[] polyA, int paramsK) {
        byte[] t = new byte[8];
        polyA = Poly.polyConditionalSubQ(polyA);
        int rr = 0;
        byte[] r;
        switch (paramsK) {
            case 2:
            case 3:
                r = new byte[KyberParams.PARAMS_POLY_COMPRESSED_BYTES_K768];
                for (int i = 0; i < KyberParams.PARAMS_N / 8; i++) {
                    for (int j = 0; j < 8; j++) {
                        t[j] = (byte) (((((polyA[8 * i + j]) << 4) + (KyberParams.PARAMS_Q / 2)) / (KyberParams.PARAMS_Q)) & 15);
                    }
                    r[rr + 0] = (byte) (t[0] | (t[1] << 4));
                    r[rr + 1] = (byte) (t[2] | (t[3] << 4));
                    r[rr + 2] = (byte) (t[4] | (t[5] << 4));
                    r[rr + 3] = (byte) (t[6] | (t[7] << 4));
                    rr = rr + 4;
                }
                break;

            default:
                r = new byte[KyberParams.PARAMS_POLY_COMPRESSED_BYTES_K1024];
                for (int i = 0; i < KyberParams.PARAMS_N / 8; i++) {
                    for (int j = 0; j < 8; j++) {
                        t[j] = (byte) (((((polyA[8 * i + j]) << 5) + (KyberParams.PARAMS_Q / 2)) / (KyberParams.PARAMS_Q)) & 31);
                    }
                    r[rr + 0] = (byte) ((t[0] >> 0) | (t[1] << 5));
                    r[rr + 1] = (byte) ((t[1] >> 3) | (t[2] << 2) | (t[3] << 7));
                    r[rr + 2] = (byte) ((t[3] >> 1) | (t[4] << 4));
                    r[rr + 3] = (byte) ((t[4] >> 4) | (t[5] << 1) | (t[6] << 6));
                    r[rr + 4] = (byte) ((t[6] >> 2) | (t[7] << 3));
                    rr = rr + 5;
                }
        }

        return r;
    }

    /**
     * De-serialize and decompress a polynomial
     *
     * Compression is lossy so the resulting polynomial will not match the
     * original polynomial
     *
     * @param a
     * @param paramsK
     * @return
     */
    public static short[] decompressPoly(byte[] a, int paramsK) {
        short[] r = new short[KyberParams.PARAMS_POLY_BYTES];
        int aa = 0;
        switch (paramsK) {
            case 2:
            case 3:
                for (int i = 0; i < KyberParams.PARAMS_N / 2; i++) {
                    r[2 * i + 0] = (short) (((((int) (a[aa] & 0xFF) & 15) * KyberParams.PARAMS_Q) + 8) >> 4);
                    r[2 * i + 1] = (short) (((((int) (a[aa] & 0xFF) >> 4) * KyberParams.PARAMS_Q) + 8) >> 4);
                    aa = aa + 1;
                }
                break;

            default:
                long[] t = new long[8];
                for (int i = 0; i < KyberParams.PARAMS_N / 8; i++) {
                    t[0] = (long) ((int) (a[aa + 0] & 0xFF) >> 0) & 0xFF;
                    t[1] = (long) ((byte) (((int) (a[aa + 0] & 0xFF) >> 5)) | (byte) ((int) (a[aa + 1] & 0xFF) << 3)) & 0xFF;
                    t[2] = (long) ((int) (a[aa + 1] & 0xFF) >> 2) & 0xFF;
                    t[3] = (long) ((byte) (((int) (a[aa + 1] & 0xFF) >> 7)) | (byte) ((int) (a[aa + 2] & 0xFF) << 1)) & 0xFF;
                    t[4] = (long) ((byte) (((int) (a[aa + 2] & 0xFF) >> 4)) | (byte) ((int) (a[aa + 3] & 0xFF) << 4)) & 0xFF;
                    t[5] = (long) ((int) (a[aa + 3] & 0xFF) >> 1) & 0xFF;
                    t[6] = (long) ((byte) (((int) (a[aa + 3] & 0xFF) >> 6)) | (byte) ((int) (a[aa + 4] & 0xFF) << 2)) & 0xFF;
                    t[7] = ((long) ((int) (a[aa + 4] & 0xFF) >> 3)) & 0xFF;
                    aa = aa + 5;
                    for (int j = 0; j < 8; j++) {
                        r[8 * i + j] = (short) ((((long) (t[j] & 31) * (KyberParams.PARAMS_Q)) + 16) >> 5);
                    }
                }
        }
        return r;
    }

    /**
     * Serialize a polynomial in to an array of bytes
     *
     * @param a
     * @return
     */
    public static byte[] polyToBytes(short[] a) {
        int t0, t1;
        byte[] r = new byte[KyberParams.PARAMS_POLY_BYTES];
        a = Poly.polyConditionalSubQ(a);
        for (int i = 0; i < KyberParams.PARAMS_N / 2; i++) {
            t0 = ((int) (a[2 * i] & 0xFFFF));
            t1 = ((int) (a[2 * i + 1]) & 0xFFFF);
            r[3 * i + 0] = (byte) (t0 >> 0);
            r[3 * i + 1] = (byte) ((int) (t0 >> 8) | (int) (t1 << 4));
            r[3 * i + 2] = (byte) (t1 >> 4);
        }
        return r;
    }

    /**
     * De-serialize a byte array into a polynomial
     *
     * @param a
     * @return
     */
    public static short[] polyFromBytes(byte[] a) {
        short[] r = new short[KyberParams.PARAMS_POLY_BYTES];
        for (int i = 0; i < KyberParams.PARAMS_N / 2; i++) {
            r[2 * i] = (short) ((((a[3 * i + 0] & 0xFF) >> 0) | ((a[3 * i + 1] & 0xFF) << 8)) & 0xFFF);
            r[2 * i + 1] = (short) ((((a[3 * i + 1] & 0xFF) >> 4) | ((a[3 * i + 2] & 0xFF) << 4)) & 0xFFF);
        }
        return r;
    }

    /**
     * Convert a 32-byte message to a polynomial
     *
     * @param msg
     * @return
     */
    public static short[] polyFromData(byte[] msg) {
        short[] r = new short[KyberParams.PARAMS_N];
        short mask;
        for (int i = 0; i < KyberParams.PARAMS_N / 8; i++) {
            for (int j = 0; j < 8; j++) {
                mask = (short) (-1 * (short) (((msg[i] & 0xFF) >> j) & 1));
                r[8 * i + j] = (short) (mask & (short) ((KyberParams.PARAMS_Q + 1) / 2));
            }
        }
        return r;
    }

    /**
     * Convert a polynomial to a 32-byte message
     *
     * @param a
     * @return
     */
    public static byte[] polyToMsg(short[] a) {
        byte[] msg = new byte[KyberParams.PARAMS_SYM_BYTES];
        int t;
        a = polyConditionalSubQ(a);
        for (int i = 0; i < KyberParams.PARAMS_N / 8; i++) {
            msg[i] = 0;
            for (int j = 0; j < 8; j++) {
                t = (int) ((((((int) (a[8 * i + j])) << 1) + (KyberParams.PARAMS_Q / 2)) / KyberParams.PARAMS_Q) & 1);
                msg[i] = (byte) (msg[i] | (t << j));
            }
        }
        return msg;
    }

    /**
     * Generate a deterministic noise polynomial from a seed and nonce
     *
     * The polynomial output will be close to a centered binomial distribution
     *
     * @param seed
     * @param nonce
     * @param paramsK
     * @return
     */
    /*
    public static short[] getNoisePoly(byte[] seed, byte nonce, int paramsK) {
        int l;
        byte[] p;
        switch (paramsK) {
            case 2:
                l = KyberParams.PARAMS_ETAK512 * KyberParams.PARAMS_N / 4;
                break;
            default:
                l = KyberParams.PARAMS_ETAK768_K1024 * KyberParams.PARAMS_N / 4;
        }

        p = Indcpa.generatePRFByteArray(l, seed, nonce);
        return ByteUtils.generateCBDPoly(p, paramsK);
    }*/

    /**
     * Computes an in-place negacyclic number-theoretic transform (NTT) of a
     * polynomial
     *
     * Input is assumed normal order
     *
     * Output is assumed bit-revered order
     *
     * @param r
     * @return
     */
    public static short[] polyNTT(short[] r) {
        return Ntt.ntt(r);
    }

    /**
     * Computes an in-place inverse of a negacyclic number-theoretic transform
     * (NTT) of a polynomial
     *
     * Input is assumed bit-revered order
     *
     * Output is assumed normal order
     *
     * @param r
     * @return
     */
    public static short[] polyInvNTTMont(short[] r) {
        return Ntt.invNTT(r);
    }

    /**
     * Multiply two polynomials in the number-theoretic transform (NTT) domain
     *
     * @param polyA
     * @param polyB
     * @return
     */
    public static short[] polyBaseMulMont(short[] polyA, short[] polyB) {
        for (int i = 0; i < KyberParams.PARAMS_N / 4; i++) {
            short[] rx = Ntt.baseMultiplier(
                    polyA[4 * i + 0], polyA[4 * i + 1],
                    polyB[4 * i + 0], polyB[4 * i + 1],
                    (short) Ntt.nttZetas[64 + i]
            );
            short[] ry = Ntt.baseMultiplier(
                    polyA[4 * i + 2], polyA[4 * i + 3],
                    polyB[4 * i + 2], polyB[4 * i + 3],
                    (short) (-1 * Ntt.nttZetas[64 + i])
            );
            polyA[4 * i + 0] = rx[0];
            polyA[4 * i + 1] = rx[1];
            polyA[4 * i + 2] = ry[0];
            polyA[4 * i + 3] = ry[1];
        }
        return polyA;
    }

    /**
     * Performs an in-place conversion of all coefficients of a polynomial from
     * the normal domain to the Montgomery domain
     *
     * @param polyR
     * @return
     */
    public static short[] polyToMont(short[] polyR) {
        for (int i = 0; i < KyberParams.PARAMS_N; i++) {
            polyR[i] = ByteUtils.montgomeryReduce((long) (polyR[i] * 1353));
        }
        return polyR;
    }

    /**
     * Apply Barrett reduction to all coefficients of this polynomial
     *
     * @param r
     * @return
     */
    public static short[] polyReduce(short[] r) {
        for (int i = 0; i < KyberParams.PARAMS_N; i++) {
            r[i] = ByteUtils.barrettReduce(r[i]);
        }
        return r;
    }

    /**
     * Apply the conditional subtraction of Q (KyberParams) to each coefficient of a
     polynomial
     *
     * @param r
     * @return
     */
    public static short[] polyConditionalSubQ(short[] r) {
        for (int i = 0; i < KyberParams.PARAMS_N; i++) {
            r[i] = ByteUtils.conditionalSubQ(r[i]);
        }
        return r;
    }

    /**
     * Add two polynomials
     *
     * @param polyA
     * @param polyB
     * @return
     */
    public static short[] polyAdd(short[] polyA, short[] polyB) {
        for (int i = 0; i < KyberParams.PARAMS_N; i++) {
            polyA[i] = (short) (polyA[i] + polyB[i]);
        }
        return polyA;
    }

    /**
     * Subtract two polynomials
     *
     * @param polyA
     * @param polyB
     * @return
     */
    public static short[] polySub(short[] polyA, short[] polyB) {
        for (int i = 0; i < KyberParams.PARAMS_N; i++) {
            polyA[i] = (short) (polyA[i] - polyB[i]);
        }
        return polyA;
    }

    /**
     * Create a new Polynomial Vector
     *
     * @param paramsK
     * @return
     */
    public static short[][] generateNewPolyVector(int paramsK) {
        short[][] pv = new short[paramsK][KyberParams.PARAMS_POLY_BYTES];
        return pv;
    }

    /**
     * Perform a lossly compression and serialization of a vector of polynomials
     *
     * @param a
     * @param paramsK
     * @return
     */
    public static byte[] compressPolyVector(short[][] a, int paramsK) {
        Poly.polyVectorCSubQ(a, paramsK);
        int rr = 0;
        byte[] r;
        long[] t;
        switch (paramsK) {
            case 2:
                r = new byte[KyberParams.PARAMS_POLYVEC_COMPRESSED_BYTES_K512];
                break;
            case 3:
                r = new byte[KyberParams.PARAMS_POLYVEC_COMPRESSED_BYTES_K768];
                break;
            default:
                r = new byte[KyberParams.PARAMS_POLYVEC_COMPRESSED_BYTES_K1024];
        }

        switch (paramsK) {
            case 2:
            case 3:
                t = new long[4];
                for (int i = 0; i < paramsK; i++) {
                    for (int j = 0; j < KyberParams.PARAMS_N / 4; j++) {
                        for (int k = 0; k < 4; k++) {
                            t[k] = ((long) (((long) ((long) (a[i][4 * j + k]) << 10) + (long) (KyberParams.PARAMS_Q / 2)) / (long) (KyberParams.PARAMS_Q)) & 0x3ff);
                        }
                        r[rr + 0] = (byte) (t[0] >> 0);
                        r[rr + 1] = (byte) ((t[0] >> 8) | (t[1] << 2));
                        r[rr + 2] = (byte) ((t[1] >> 6) | (t[2] << 4));
                        r[rr + 3] = (byte) ((t[2] >> 4) | (t[3] << 6));
                        r[rr + 4] = (byte) ((t[3] >> 2));
                        rr = rr + 5;
                    }
                }
                break;

            default:
                t = new long[8];
                for (int i = 0; i < paramsK; i++) {
                    for (int j = 0; j < KyberParams.PARAMS_N / 8; j++) {
                        for (int k = 0; k < 8; k++) {
                            t[k] = ((long) (((long) ((long) (a[i][8 * j + k]) << 11) + (long) (KyberParams.PARAMS_Q / 2)) / (long) (KyberParams.PARAMS_Q)) & 0x7ff);
                        }
                        r[rr + 0] = (byte) ((t[0] >> 0));
                        r[rr + 1] = (byte) ((t[0] >> 8) | (t[1] << 3));
                        r[rr + 2] = (byte) ((t[1] >> 5) | (t[2] << 6));
                        r[rr + 3] = (byte) ((t[2] >> 2));
                        r[rr + 4] = (byte) ((t[2] >> 10) | (t[3] << 1));
                        r[rr + 5] = (byte) ((t[3] >> 7) | (t[4] << 4));
                        r[rr + 6] = (byte) ((t[4] >> 4) | (t[5] << 7));
                        r[rr + 7] = (byte) ((t[5] >> 1));
                        r[rr + 8] = (byte) ((t[5] >> 9) | (t[6] << 2));
                        r[rr + 9] = (byte) ((t[6] >> 6) | (t[7] << 5));
                        r[rr + 10] = (byte) ((t[7] >> 3));
                        rr = rr + 11;
                    }
                }
        }
        return r;
    }

    /**
     * De-serialize and decompress a vector of polynomials
     *
     * Since the compress is lossy, the results will not be exactly the same as
     * the original vector of polynomials
     *
     * @param a
     * @param paramsK
     * @return
     */
    public static short[][] decompressPolyVector(byte[] a, int paramsK) {
        short[][] r = new short[paramsK][KyberParams.PARAMS_POLY_BYTES];
        int aa = 0;
        int[] t;
        switch (paramsK) {
            case 2:
            case 3:
                t = new int[4]; // has to be unsigned..
                for (int i = 0; i < paramsK; i++) {
                    for (int j = 0; j < (KyberParams.PARAMS_N / 4); j++) {
                        t[0] = ((a[aa + 0] & 0xFF) >> 0) | ((a[aa + 1] & 0xFF) << 8);
                        t[1] = ((a[aa + 1] & 0xFF) >> 2) | ((a[aa + 2] & 0xFF) << 6);
                        t[2] = ((a[aa + 2] & 0xFF) >> 4) | ((a[aa + 3] & 0xFF) << 4);
                        t[3] = ((a[aa + 3] & 0xFF) >> 6) | ((a[aa + 4] & 0xFF) << 2);
                        aa = aa + 5;
                        for (int k = 0; k < 4; k++) {
                            r[i][4 * j + k] = (short) (((long) (t[k] & 0x3FF) * (long) (KyberParams.PARAMS_Q) + 512) >> 10);
                        }
                    }
                }
                break;

            default:
                t = new int[8]; // has to be unsigned..
                for (int i = 0; i < paramsK; i++) {
                    for (int j = 0; j < (KyberParams.PARAMS_N / 8); j++) {
                        t[0] = (((a[aa + 0] & 0xff) >> 0) | ((a[aa + 1] & 0xff) << 8));
                        t[1] = (((a[aa + 1] & 0xff) >> 3) | ((a[aa + 2] & 0xff) << 5));
                        t[2] = (((a[aa + 2] & 0xff) >> 6) | ((a[aa + 3] & 0xff) << 2) | ((a[aa + 4] & 0xff) << 10));
                        t[3] = (((a[aa + 4] & 0xff) >> 1) | ((a[aa + 5] & 0xff) << 7));
                        t[4] = (((a[aa + 5] & 0xff) >> 4) | ((a[aa + 6] & 0xff) << 4));
                        t[5] = (((a[aa + 6] & 0xff) >> 7) | ((a[aa + 7] & 0xff) << 1) | ((a[aa + 8] & 0xff) << 9));
                        t[6] = (((a[aa + 8] & 0xff) >> 2) | ((a[aa + 9] & 0xff) << 6));
                        t[7] = (((a[aa + 9] & 0xff) >> 5) | ((a[aa + 10] & 0xff) << 3));
                        aa = aa + 11;
                        for (int k = 0; k < 8; k++) {
                            r[i][8 * j + k] = (short) (((long) (t[k] & 0x7FF) * (long) (KyberParams.PARAMS_Q) + 1024) >> 11);
                        }
                    }
                }
        }
        return r;
    }

    /**
     * Serialize a polynomial vector to a byte array
     *
     * @param polyA
     * @param paramsK
     * @return
     */
    public static byte[] polyVectorToBytes(short[][] polyA, int paramsK) {
        byte[] r = new byte[paramsK * KyberParams.PARAMS_POLY_BYTES];
        for (int i = 0; i < paramsK; i++) {
            byte[] byteA = polyToBytes(polyA[i]);
            System.arraycopy(byteA, 0, r, i * KyberParams.PARAMS_POLY_BYTES, byteA.length);
        }
        return r;
    }

    /**
     * Deserialize a byte array into a polynomial vector
     *
     * @param polyA
     * @param paramsK
     * @return
     */
    public static short[][] polyVectorFromBytes(byte[] polyA, int paramsK) {
        short[][] r = new short[paramsK][KyberParams.PARAMS_POLY_BYTES];
        for (int i = 0; i < paramsK; i++) {
            int start = (i * KyberParams.PARAMS_POLY_BYTES);
            int end = (i + 1) * KyberParams.PARAMS_POLY_BYTES;
            r[i] = Poly.polyFromBytes(Arrays.copyOfRange(polyA, start, end));
        }
        return r;
    }

    /**
     * Applies forward number-theoretic transforms (NTT) to all elements of a
     * vector of polynomial
     *
     * @param r
     * @param paramsK
     * @return
     */
    public static short[][] polyVectorNTT(short[][] r, int paramsK) {
        for (int i = 0; i < paramsK; i++) {
            r[i] = Poly.polyNTT(r[i]);
        }
        return r;
    }

    /**
     * Applies the inverse number-theoretic transform (NTT) to all elements of a
     * vector of polynomials and multiplies by Montgomery factor 2^16
     *
     * @param r
     * @param paramsK
     * @return
     */
    public static short[][] polyVectorInvNTTMont(short[][] r, int paramsK) {
        for (int i = 0; i < paramsK; i++) {
            r[i] = Poly.polyInvNTTMont(r[i]);
        }
        return r;
    }

    /**
     * Pointwise-multiplies elements of the given polynomial-vectors ,
     * accumulates the results , and then multiplies by 2^-16
     *
     * @param polyA
     * @param polyB
     * @param paramsK
     * @return
     */
    public static short[] polyVectorPointWiseAccMont(short[][] polyA, short[][] polyB, int paramsK) {
        short[] r = Poly.polyBaseMulMont(polyA[0], polyB[0]);
        for (int i = 1; i < paramsK; i++) {
            short[] t = Poly.polyBaseMulMont(polyA[i], polyB[i]);
            r = Poly.polyAdd(r, t);
        }
        return polyReduce(r);
    }

    /**
     * Applies Barrett reduction to each coefficient of each element of a vector
     * of polynomials.
     *
     * @param r
     * @param paramsK
     * @return
     */
    public static short[][] polyVectorReduce(short[][] r, int paramsK) {
        for (int i = 0; i < paramsK; i++) {
            r[i] = Poly.polyReduce(r[i]);
        }
        return r;
    }

    /**
     * Applies the conditional subtraction of Q (KyberParams) to each coefficient of
     each element of a vector of polynomials.
     */
    public static short[][] polyVectorCSubQ(short[][] r, int paramsK) {
        for (int i = 0; i < paramsK; i++) {
            r[i] = Poly.polyConditionalSubQ(r[i]);
        }
        return r;
    }

    /**
     * Add two polynomial vectors
     *
     * @param polyA
     * @param polyB
     * @param paramsK
     * @return
     */
    public static short[][] polyVectorAdd(short[][] polyA, short[][] polyB, int paramsK) {
        for (int i = 0; i < paramsK; i++) {
            polyA[i] = Poly.polyAdd(polyA[i], polyB[i]);
        }
        return polyA;
    }
}
