package org.sectorrent.jlibcrypto.kyber;

import java.security.InvalidKeyException;
import java.security.Key;

public class KyberEncrypted implements Key {

    private KyberSecretKey secretKey;
    private KyberCipherText cipherText;

    /**
     * Default constructor
     */
    public KyberEncrypted() {

    }

    /**
     *
     * @param sharedSecret
     * @param cipherText
     */
    public KyberEncrypted(KyberSecretKey sharedSecret, KyberCipherText cipherText) {
        this.secretKey = sharedSecret;
        this.cipherText = cipherText;
    }

    /**
     *
     * @param encodedBytes
     * @throws InvalidKeyException
     */
    public KyberEncrypted(byte[] encodedBytes) throws InvalidKeyException {
        byte[] encodedSecret = new byte[KyberParams.KYBER_ENCODED_SS_BYTES];
        System.arraycopy(encodedBytes, 0, encodedSecret, 0, KyberParams.KYBER_ENCODED_SS_BYTES);
        this.secretKey = new KyberSecretKey(encodedSecret);

        int cipherLen = encodedBytes.length - KyberParams.KYBER_ENCODED_SS_BYTES;
        byte[] encodedCipher = new byte[cipherLen];
        System.arraycopy(encodedBytes, KyberParams.KYBER_ENCODED_SS_BYTES, encodedCipher, 0, cipherLen);
        this.cipherText = new KyberCipherText(encodedCipher);
    }

    /**
     *
     * @return
     */
    @Override
    public byte[] getEncoded() {
        byte[] encodedSecret = this.secretKey.getEncoded();
        byte[] encodedCipher = this.cipherText.getEncoded();
        byte[] returnArray = new byte[encodedSecret.length + encodedCipher.length];
        System.arraycopy(encodedSecret, 0, returnArray, 0, encodedSecret.length);
        System.arraycopy(encodedCipher, 0, returnArray, encodedSecret.length, encodedCipher.length);
        return returnArray;
    }

    /**
     * @return the secretKey
     */
    public KyberSecretKey getSecretKey() {
        return secretKey;
    }

    /**
     * @param secretKey the secretKey to set
     */
    public void setSecretKey(KyberSecretKey secretKey) {
        this.secretKey = secretKey;
    }

    /**
     * @return the cipherText
     */
    public KyberCipherText getCipherText() {
        return cipherText;
    }

    /**
     * @param cipherText the cipherText to set
     */
    public void setCipherText(KyberCipherText cipherText) {
        this.cipherText = cipherText;
    }

    @Override
    public String getAlgorithm() {
        return "Kyber";
    }

    @Override
    public String getFormat() {
        return "X.509";
    }
}
