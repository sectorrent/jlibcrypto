package org.sectorrent.jlibcrypto.kyber;

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
        return null;
    }

    private KyberPKI generateKeys512(SecureRandom rand){
        int paramsK = 2;
        KyberPKI kyberPKI = new KyberPKI();
        //try{
        /*
            KyberPackedPKI indcpaPKI = Indcpa.generateKyberKeys(paramsK);
            byte[] packedPublicKey = indcpaPKI.getPackedPublicKey();
            byte[] packedPrivateKey = indcpaPKI.getPackedPrivateKey();
            byte[] privateKeyFixedLength = new byte[KyberParams.Kyber512SKBytes];
            MessageDigest md = MessageDigest.getInstance("SHA3-256");
            byte[] encodedHash = md.digest(packedPublicKey);
            byte[] pkh = new byte[encodedHash.length];
            System.arraycopy(encodedHash, 0, pkh, 0, encodedHash.length);
            byte[] rnd = new byte[KyberParams.paramsSymBytes];
            rand.nextBytes(rnd);
            int offsetEnd = packedPrivateKey.length;
            System.arraycopy(packedPrivateKey, 0, privateKeyFixedLength, 0, offsetEnd);
            System.arraycopy(packedPublicKey, 0, privateKeyFixedLength, offsetEnd, packedPublicKey.length);
            offsetEnd = offsetEnd + packedPublicKey.length;
            System.arraycopy(pkh, 0, privateKeyFixedLength, offsetEnd, pkh.length);
            offsetEnd += pkh.length;
            System.arraycopy(rnd, 0, privateKeyFixedLength, offsetEnd, rnd.length);
            kyberPKI.setPublicKey(new KyberPublicKey(packedPublicKey, null, null));
            kyberPKI.setPrivateKey(new KyberPrivateKey(privateKeyFixedLength, null, null));
            /*
        }catch(Exception ex){
            System.out.println("generateKeys512 Exception! [" + ex.getMessage() + "]");
            ex.printStackTrace();
        }*/
        return kyberPKI;
    }
}
