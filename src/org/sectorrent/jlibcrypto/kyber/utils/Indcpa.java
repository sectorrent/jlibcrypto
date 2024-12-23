package org.sectorrent.jlibcrypto.kyber.utils;

import org.sectorrent.jlibcrypto.hash.SHAKE_128;
import org.sectorrent.jlibcrypto.hash.SHAKE_256;
import org.sectorrent.jlibcrypto.kyber.KyberPackedPKI;
import org.sectorrent.jlibcrypto.kyber.KyberParams;
import org.sectorrent.jlibcrypto.kyber.KyberUniformRandom;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

public class Indcpa {

    /**
     * Pack the public key with the given public key and seed into a polynomial
     * vector
     *
     * @param publicKey
     * @param seed
     * @param paramsK
     * @return
     */
    public static byte[] packPublicKey(short[][] publicKey, byte[] seed, int paramsK) {
        byte[] initialArray = Poly.polyVectorToBytes(publicKey, paramsK);
        byte[] packedPublicKey;
        switch (paramsK) {
            case 2:
                packedPublicKey = new byte[KyberParams.PARAMS_INDCPA_PUBLIC_KEY_BYTES_K512];
                System.arraycopy(initialArray, 0, packedPublicKey, 0, initialArray.length);
                System.arraycopy(seed, 0, packedPublicKey, initialArray.length, seed.length);
                break;
            case 3:
                packedPublicKey = new byte[KyberParams.PARAMS_INDCPA_PUBLIC_KEY_BYTES_K768];
                System.arraycopy(initialArray, 0, packedPublicKey, 0, initialArray.length);
                System.arraycopy(seed, 0, packedPublicKey, initialArray.length, seed.length);
                break;
            default:
                packedPublicKey = new byte[KyberParams.PARAMS_INDCPA_PUBLIC_KEY_BYTES_K1024];
                System.arraycopy(initialArray, 0, packedPublicKey, 0, initialArray.length);
                System.arraycopy(seed, 0, packedPublicKey, initialArray.length, seed.length);
        }

        return packedPublicKey;
    }

    /**
     * Unpack the packed public key into the public key polynomial vector and
     * see
     *
     * @param packedPublicKey
     * @param paramsK
     * @return
     */
    public static UnpackedPublicKey unpackPublicKey(byte[] packedPublicKey, int paramsK) {
        UnpackedPublicKey unpackedKey = new UnpackedPublicKey();
        switch (paramsK) {
            case 2:
                unpackedKey.setPublicKeyPolyvec(Poly.polyVectorFromBytes(Arrays.copyOfRange(packedPublicKey, 0, KyberParams.PARAMS_POLYVEC_BYTES_K512), paramsK));
                unpackedKey.setSeed(Arrays.copyOfRange(packedPublicKey, KyberParams.PARAMS_POLYVEC_BYTES_K512, packedPublicKey.length));
                break;
            case 3:
                unpackedKey.setPublicKeyPolyvec(Poly.polyVectorFromBytes(Arrays.copyOfRange(packedPublicKey, 0, KyberParams.PARAMS_POLYVEC_BYTES_K768), paramsK));
                unpackedKey.setSeed(Arrays.copyOfRange(packedPublicKey, KyberParams.PARAMS_POLYVEC_BYTES_K768, packedPublicKey.length));
                break;
            default:
                unpackedKey.setPublicKeyPolyvec(Poly.polyVectorFromBytes(Arrays.copyOfRange(packedPublicKey, 0, KyberParams.PARAMS_POLYVEC_BYTES_K1024), paramsK));
                unpackedKey.setSeed(Arrays.copyOfRange(packedPublicKey, KyberParams.PARAMS_POLYVEC_BYTES_K1024, packedPublicKey.length));
        }
        return unpackedKey;
    }

    /**
     * Pack the private key into a byte array
     *
     * @param privateKey
     * @param paramsK
     * @return
     */
    public static byte[] packPrivateKey(short[][] privateKey, int paramsK) {
        byte[] packedPrivateKey = Poly.polyVectorToBytes(privateKey, paramsK);
        return packedPrivateKey;
    }

    /**
     * Unpack the private key byte array into a polynomial vector
     *
     * @param packedPrivateKey
     * @param paramsK
     * @return
     */
    public static short[][] unpackPrivateKey(byte[] packedPrivateKey, int paramsK) {
        short[][] unpackedPrivateKey = Poly.polyVectorFromBytes(packedPrivateKey, paramsK);
        return unpackedPrivateKey;
    }

    /**
     * Pack the ciphertext into a byte array
     *
     * @param b
     * @param v
     * @param paramsK
     * @return
     */
    public static byte[] packCiphertext(short[][] b, short[] v, int paramsK) {
        byte[] bCompress = Poly.compressPolyVector(b, paramsK);
        byte[] vCompress = Poly.compressPoly(v, paramsK);
        byte[] returnArray = new byte[bCompress.length + vCompress.length];
        System.arraycopy(bCompress, 0, returnArray, 0, bCompress.length);
        System.arraycopy(vCompress, 0, returnArray, bCompress.length, vCompress.length);
        return returnArray;
    }

    /**
     * Unpack the ciphertext from a byte array into a polynomial vector and
     * vector
     *
     * @param c
     * @param paramsK
     */
    public static UnpackedCipherBytes unpackCiphertext(byte[] c, int paramsK) {
        UnpackedCipherBytes unpackedCipherText = new UnpackedCipherBytes();
        byte[] bpc;
        byte[] vc;
        switch (paramsK) {
            case 2:
                bpc = new byte[KyberParams.PARAMS_POLYVEC_COMPRESSED_BYTES_K512];
                break;
            case 3:
                bpc = new byte[KyberParams.PARAMS_POLYVEC_COMPRESSED_BYTES_K768];
                break;
            default:
                bpc = new byte[KyberParams.PARAMS_POLYVEC_COMPRESSED_BYTES_K1024];
        }
        System.arraycopy(c, 0, bpc, 0, bpc.length);
        vc = new byte[c.length - bpc.length];
        System.arraycopy(c, bpc.length, vc, 0, vc.length);
        unpackedCipherText.setBp(Poly.decompressPolyVector(bpc, paramsK));
        unpackedCipherText.setV(Poly.decompressPoly(vc, paramsK));

        return unpackedCipherText;
    }

    /**
     * Runs rejection sampling on uniform random bytes to generate uniform
     * random integers modulo `Q`
     *
     * @param uniformRandom
     * @param buf
     * @param bufl
     * @param l
     * @return
     */
    public static void generateUniform(KyberUniformRandom uniformRandom, byte[] buf, int bufl, int l) {
        short[] uniformR = new short[KyberParams.PARAMS_POLY_BYTES];
        int d1;
        int d2;
        int uniformI = 0; // Always start at 0
        int j = 0;
        while ((uniformI < l) && ((j + 3) <= bufl)) {
            d1 = (int) (((((int) (buf[j] & 0xFF)) >> 0) | (((int) (buf[j + 1] & 0xFF)) << 8)) & 0xFFF);
            d2 = (int) (((((int) (buf[j + 1] & 0xFF)) >> 4) | (((int) (buf[j + 2] & 0xFF)) << 4)) & 0xFFF);
            j = j + 3;
            if (d1 < (int) KyberParams.PARAMS_Q) {
                uniformR[uniformI] = (short) d1;
                uniformI++;
            }
            if (uniformI < l && d2 < (int) KyberParams.PARAMS_Q) {
                uniformR[uniformI] = (short) d2;
                uniformI++;
            }
        }
        uniformRandom.setUniformI(uniformI);
        uniformRandom.setUniformR(uniformR);
    }

    /**
     * Generate a polynomial vector matrix from the given seed
     *
     * @param seed
     * @param transposed
     * @param paramsK
     * @return
     */
    public static short[][][] generateMatrix(byte[] seed, boolean transposed, int paramsK) {
        short[][][] r = new short[paramsK][paramsK][KyberParams.PARAMS_POLY_BYTES];
        byte[] buf = new byte[672];
        KyberUniformRandom uniformRandom = new KyberUniformRandom();
        byte[] s = new byte[seed.length+2];
        System.arraycopy(seed, 0, s, 0, seed.length);

        for (int i = 0; i < paramsK; i++) {
            r[i] = Poly.generateNewPolyVector(paramsK);
            for (int j = 0; j < paramsK; j++) {
                if (transposed) {
                    s[seed.length] = (byte) i;
                    s[seed.length+1] = (byte) j;

                } else {
                    s[seed.length] = (byte) j;
                    s[seed.length+1] = (byte) i;
                }

                buf = SHAKE_128.getHash(buf.length, s);

                generateUniform(uniformRandom, Arrays.copyOfRange(buf, 0, 504), 504, KyberParams.PARAMS_N);
                int ui = uniformRandom.getUniformI();
                r[i][j] = uniformRandom.getUniformR();

                while (ui < KyberParams.PARAMS_N) {
                    generateUniform(uniformRandom, Arrays.copyOfRange(buf, 504, 672), 168, KyberParams.PARAMS_N - ui);
                    int ctrn = uniformRandom.getUniformI();
                    short[] missing = uniformRandom.getUniformR();
                    for (int k = ui; k < KyberParams.PARAMS_N; k++) {
                        r[i][j][k] = missing[k - ui];
                    }
                    ui = ui + ctrn;
                }
            }
        }
        return r;
    }

    /**
     * Pseudo-random function to derive a deterministic array of random bytes
     * from the supplied secret key object and other parameters.
     *
     * @param l
     * @param key
     * @param nonce
     * @return
     */
    public static byte[] generatePRFByteArray(int l, byte[] key, byte nonce) {
        byte[] newKey = new byte[key.length + 1];
        System.arraycopy(key, 0, newKey, 0, key.length);
        newKey[key.length] = nonce;
        return SHAKE_256.getHash(l, newKey);
    }

    /**
     * Generates public and private keys for the CPA-secure public-key
     * encryption scheme underlying Kyber.
     */
    public static KyberPackedPKI generateKyberKeys(int paramsK) {
        KyberPackedPKI packedPKI = new KyberPackedPKI();
        try {
            short[][] skpv = Poly.generateNewPolyVector(paramsK);
            short[][] pkpv = Poly.generateNewPolyVector(paramsK);
            short[][] e = Poly.generateNewPolyVector(paramsK);
            byte[] publicSeed = new byte[KyberParams.PARAMS_SYM_BYTES];
            byte[] noiseSeed = new byte[KyberParams.PARAMS_SYM_BYTES];

            MessageDigest h = MessageDigest.getInstance("SHA3-512");
            //SecureRandom sr = SecureRandom.getInstanceStrong();
            //sr.nextBytes(publicSeed);
            byte[] fullSeed = h.digest(publicSeed);

            System.arraycopy(fullSeed, 0, publicSeed, 0, KyberParams.PARAMS_SYM_BYTES);
            System.arraycopy(fullSeed, KyberParams.PARAMS_SYM_BYTES, noiseSeed, 0, KyberParams.PARAMS_SYM_BYTES);
            short[][][] a = generateMatrix(publicSeed, false, paramsK);
            byte nonce = (byte) 0;

            for (int i = 0; i < paramsK; i++) {
                skpv[i] = Poly.getNoisePoly(noiseSeed, nonce, paramsK);
                nonce = (byte) (nonce + (byte) 1);
            }

            for (int i = 0; i < paramsK; i++) {
                e[i] = Poly.getNoisePoly(noiseSeed, nonce, paramsK);
                nonce = (byte) (nonce + (byte) 1);
            }

            skpv = Poly.polyVectorNTT(skpv, paramsK);
            skpv = Poly.polyVectorReduce(skpv, paramsK);
            e = Poly.polyVectorNTT(e, paramsK);

            for (int i = 0; i < paramsK; i++) {
                short[] temp = Poly.polyVectorPointWiseAccMont(a[i], skpv, paramsK);
                pkpv[i] = Poly.polyToMont(temp);
            }

            pkpv = Poly.polyVectorAdd(pkpv, e, paramsK);
            pkpv = Poly.polyVectorReduce(pkpv, paramsK);
            packedPKI.setPackedPrivateKey(packPrivateKey(skpv, paramsK));
            packedPKI.setPackedPublicKey(packPublicKey(pkpv, publicSeed, paramsK));

        } catch (Exception ex) {
            System.out.println("generateKyberKeys Exception! [" + ex.getMessage() + "]");
            ex.printStackTrace();
        }
        return packedPKI;
    }

    /**
     * Encrypt the given message using the Kyber public-key encryption scheme
     *
     * @param m
     * @param publicKey
     * @param coins
     * @param paramsK
     * @return
     */
    public static byte[] encrypt(byte[] m, byte[] publicKey, byte[] coins, int paramsK) {
        short[][] sp = Poly.generateNewPolyVector(paramsK);
        short[][] ep = Poly.generateNewPolyVector(paramsK);
        short[][] bp = Poly.generateNewPolyVector(paramsK);
        UnpackedPublicKey unpackedPublicKey = unpackPublicKey(publicKey, paramsK);
        short[] k = Poly.polyFromData(m);
        short[][][] at = generateMatrix(Arrays.copyOfRange(unpackedPublicKey.getSeed(), 0, KyberParams.PARAMS_SYM_BYTES), true, paramsK);

        for (int i = 0; i < paramsK; i++) {
            sp[i] = Poly.getNoisePoly(coins, (byte) (i), paramsK);
            ep[i] = Poly.getNoisePoly(coins, (byte) (i + paramsK), 3);
        }

        short[] epp = Poly.getNoisePoly(coins, (byte) (paramsK * 2), 3);
        sp = Poly.polyVectorNTT(sp, paramsK);
        sp = Poly.polyVectorReduce(sp, paramsK);
        for (int i = 0; i < paramsK; i++) {
            bp[i] = Poly.polyVectorPointWiseAccMont(at[i], sp, paramsK);
        }
        short[] v = Poly.polyVectorPointWiseAccMont(unpackedPublicKey.getPublicKeyPolyvec(), sp, paramsK);
        bp = Poly.polyVectorInvNTTMont(bp, paramsK);
        v = Poly.polyInvNTTMont(v);
        bp = Poly.polyVectorAdd(bp, ep, paramsK);
        v = Poly.polyAdd(Poly.polyAdd(v, epp), k);
        bp = Poly.polyVectorReduce(bp, paramsK);

        return packCiphertext(bp, Poly.polyReduce(v), paramsK);
    }

    /**
     * Decrypt the given byte array using the Kyber public-key encryption scheme
     *
     * @param packedCipherText
     * @param privateKey
     * @param paramsK
     * @return
     */
    public static byte[] decrypt(byte[] packedCipherText, byte[] privateKey, int paramsK) {
        UnpackedCipherBytes unpackedCipherText = unpackCiphertext(packedCipherText, paramsK);
        short[][] bp = unpackedCipherText.getBp();
        short[] v = unpackedCipherText.getV();
        short[][] unpackedPrivateKey = unpackPrivateKey(privateKey, paramsK);
        bp = Poly.polyVectorNTT(bp, paramsK);
        short[] mp = Poly.polyVectorPointWiseAccMont(unpackedPrivateKey, bp, paramsK);
        mp = Poly.polyInvNTTMont(mp);
        mp = Poly.polySub(v, mp);
        mp = Poly.polyReduce(mp);
        return Poly.polyToMsg(mp);
    }
}
