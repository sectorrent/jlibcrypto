package org.sectorrent.jlibcrypto.kyber;

import org.sectorrent.jlibcrypto.kyber.utils.Indcpa;

import java.security.*;

public class Kyber512KeyPairGenerator extends KeyPairGeneratorSpi {

    private SecureRandom random;
    private int keySize;

    @Override
    public void initialize(int keysize, SecureRandom random){
        if(keysize != 512){
            throw new InvalidParameterException("Kyber key size must be 512.");
        }

        this.random = random;
    }

    @Override
    public KeyPair generateKeyPair(){
        KyberPKI kyberPKI = generateKeys();
        return new KeyPair(kyberPKI.getPublicKey(), kyberPKI.getPrivateKey());
    }

    private KyberPKI generateKeys(){
        int paramsK = 2;

        try{
            KyberPackedPKI indcpaPKI = Indcpa.generateKyberKeys(paramsK);
            byte[] packedPublicKey = indcpaPKI.getPackedPublicKey();
            byte[] packedPrivateKey = indcpaPKI.getPackedPrivateKey();
            byte[] privateKeyFixedLength = new byte[KyberParams.KYBER_512SK_BYTES];

            MessageDigest md = MessageDigest.getInstance("SHA3-256");
            byte[] encodedHash = md.digest(packedPublicKey);
            byte[] pkh = new byte[encodedHash.length];
            System.arraycopy(encodedHash, 0, pkh, 0, encodedHash.length);
            byte[] rnd = new byte[KyberParams.PARAMS_SYM_BYTES];
            //random.nextBytes(rnd);
            int offsetEnd = packedPrivateKey.length;
            System.arraycopy(packedPrivateKey, 0, privateKeyFixedLength, 0, offsetEnd);
            System.arraycopy(packedPublicKey, 0, privateKeyFixedLength, offsetEnd, packedPublicKey.length);
            offsetEnd = offsetEnd + packedPublicKey.length;
            System.arraycopy(pkh, 0, privateKeyFixedLength, offsetEnd, pkh.length);
            offsetEnd += pkh.length;
            System.arraycopy(rnd, 0, privateKeyFixedLength, offsetEnd, rnd.length);

            System.out.println("PK A: "+bytesToHex(packedPublicKey));
            System.out.println("SK A: "+bytesToHex(packedPrivateKey));

            return new KyberPKI(new KyberPublicKey(packedPublicKey), new KyberPrivateKey(privateKeyFixedLength));

        }catch(Exception ex){
            ex.printStackTrace();
            throw new RuntimeException("generateKeys512 Exception! [" + ex.getMessage() + "]");
        }
    }

    // Helper function to convert bytes to a hex string
    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xFF & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
