package org.sectorrent.jlibcrypto.kyber.utils;

import org.sectorrent.jlibcrypto.kyber.KyberParams;

import java.security.MessageDigest;
import java.security.SecureRandom;

public class Indcpa {

    /*
    public static KyberPackedPKI generateKyberKeys(int paramsK) {
        KyberPackedPKI packedPKI = new KyberPackedPKI();

        try{
            short[][] skpv = Poly.generateNewPolyVector(paramsK);
            short[][] pkpv = Poly.generateNewPolyVector(paramsK);
            short[][] e = Poly.generateNewPolyVector(paramsK);
            byte[] publicSeed = new byte[KyberParams.PARAMS_SYM_BYTES];
            byte[] noiseSeed = new byte[KyberParams.PARAMS_SYM_BYTES];

            MessageDigest h = MessageDigest.getInstance("SHA3-512");
            SecureRandom sr = SecureRandom.getInstanceStrong();
            sr.nextBytes(publicSeed);
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

        }catch(Exception ex){
            System.out.println("generateKyberKeys Exception! [" + ex.getMessage() + "]");
            ex.printStackTrace();
        }

        return packedPKI;
    }

    public static byte[] generatePRFByteArray(int l, byte[] key, byte nonce){
        byte[] hash = new byte[l];
        KeccakSponge xof = new Shake256();
        byte[] newKey = new byte[key.length + 1];
        System.arraycopy(key, 0, newKey, 0, key.length);
        newKey[key.length] = nonce;
        xof.getAbsorbStream().write(newKey);
        xof.getSqueezeStream().read(hash);
        return hash;
    }
    */
}
