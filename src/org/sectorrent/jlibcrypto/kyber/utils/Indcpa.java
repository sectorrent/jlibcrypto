package org.sectorrent.jlibcrypto.kyber.utils;

import java.security.MessageDigest;
import java.security.SecureRandom;

public class Indcpa {

    /*
    public static KyberPackedPKI generateKyberKeys(int paramsK) {
        KyberPackedPKI packedPKI = new KyberPackedPKI();
        try {
            short[][] skpv = Poly.generateNewPolyVector(paramsK);
            short[][] pkpv = Poly.generateNewPolyVector(paramsK);
            short[][] e = Poly.generateNewPolyVector(paramsK);
            byte[] publicSeed = new byte[KyberParams.paramsSymBytes];
            byte[] noiseSeed = new byte[KyberParams.paramsSymBytes];

            MessageDigest h = MessageDigest.getInstance("SHA3-512");
            SecureRandom sr = SecureRandom.getInstanceStrong();
            sr.nextBytes(publicSeed);
            byte[] fullSeed = h.digest(publicSeed);

            System.arraycopy(fullSeed, 0, publicSeed, 0, KyberParams.paramsSymBytes);
            System.arraycopy(fullSeed, KyberParams.paramsSymBytes, noiseSeed, 0, KyberParams.paramsSymBytes);
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
    */
}
