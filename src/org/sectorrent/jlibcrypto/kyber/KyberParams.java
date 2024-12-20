package org.sectorrent.jlibcrypto.kyber;

public class KyberParams {

    public final static int PARAMS_N = 256;
    public final static int PARAMS_Q = 3329;
    public final static int PARAMS_QINV = 62209;
    public final static int PARAMS_SYM_BYTES = 32;
    public final static int PARAMS_POLY_BYTES = 384;
    public final static int PARAMS_ETAK512 = 3;
    public final static int PARAMS_ETAK768_K1024 = 2;
    public final static int PARAMS_POLYVEC_BYTES_K512 = 2 * PARAMS_POLY_BYTES;
    public final static int PARAMS_POLYVEC_BYTES_K768 = 3 * PARAMS_POLY_BYTES;
    public final static int PARAMS_POLYVEC_BYTES_K1024 = 4 * PARAMS_POLY_BYTES;
    public final static int PARAMS_POLY_COMPRESSED_BYTES_K512 = 128;
    public final static int PARAMS_POLY_COMPRESSED_BYTES_K768 = 128;
    public final static int PARAMS_POLY_COMPRESSED_BYTES_K1024 = 160;
    public final static int PARAMS_POLYVEC_COMPRESSED_BYTES_K512 = 2 * 320;
    public final static int PARAMS_POLYVEC_COMPRESSED_BYTES_K768 = 3 * 320;
    public final static int PARAMS_POLYVEC_COMPRESSED_BYTES_K1024 = 4 * 352;
    public final static int PARAMS_INDCPA_PUBLIC_KEY_BYTES_K512 = PARAMS_POLYVEC_BYTES_K512 + PARAMS_SYM_BYTES;
    public final static int PARAMS_INDCPA_PUBLIC_KEY_BYTES_K768 = PARAMS_POLYVEC_BYTES_K768 + PARAMS_SYM_BYTES;
    public final static int PARAMS_INDCPA_PUBLIC_KEY_BYTES_K1024 = PARAMS_POLYVEC_BYTES_K1024 + PARAMS_SYM_BYTES;
    public final static int PARAMS_INDCPA_SECRET_KEY_BYTES_K512 = 2 * PARAMS_POLY_BYTES;
    public final static int PARAMS_INDCPA_SECRET_KEY_BYTES_K768 = 3 * PARAMS_POLY_BYTES;
    public final static int PARAMS_INDCPA_SECRET_KEY_BYTES_K1024 = 4 * PARAMS_POLY_BYTES;

    // Kyber512SKBytes is a constant representing the byte length of private keys in Kyber-512
    public final static int KYBER_512SK_BYTES = PARAMS_POLYVEC_BYTES_K512 + ((PARAMS_POLYVEC_BYTES_K512 + PARAMS_SYM_BYTES) + 2 * PARAMS_SYM_BYTES);

    // Kyber768SKBytes is a constant representing the byte length of private keys in Kyber-768
    public final static int KYBER_768SK_BYTES = PARAMS_POLYVEC_BYTES_K768 + ((PARAMS_POLYVEC_BYTES_K768 + PARAMS_SYM_BYTES) + 2 * PARAMS_SYM_BYTES);

    // Kyber1024SKBytes is a constant representing the byte length of private keys in Kyber-1024
    public final static int KYBER_1024SK_BYTES = PARAMS_POLYVEC_BYTES_K1024 + ((PARAMS_POLYVEC_BYTES_K1024 + PARAMS_SYM_BYTES) + 2 * PARAMS_SYM_BYTES);

    // Kyber512PKBytes is a constant representing the byte length of public keys in Kyber-512
    public final static int KYBER_512PK_BYTES = PARAMS_POLYVEC_BYTES_K512 + PARAMS_SYM_BYTES;

    // Kyber768PKBytes is a constant representing the byte length of public keys in Kyber-768
    public final static int KYBER_768PK_BYTES = PARAMS_POLYVEC_BYTES_K768 + PARAMS_SYM_BYTES;

    // Kyber1024PKBytes is a constant representing the byte length of public keys in Kyber-1024
    public final static int KYBER_1024PK_BYTES = PARAMS_POLYVEC_BYTES_K1024 + PARAMS_SYM_BYTES;

    // KyberEncoded512PKBytes is a constant representing the byte length of encoded public keys in Kyber-512
    public final static int KYBER_ENCODED_512PK_BYTES = 967;

    // KyberEncoded768PKBytes is a constant representing the byte length of encoded public keys in Kyber-768
    public final static int KYBER_ENCODED_768PK_BYTES = 1351;

    // KyberEncoded1024PKBytes is a constant representing the byte length of encoded public keys in Kyber-1024
    public final static int KYBER_ENCODED_1024PK_BYTES = 1735;

    // Kyber512CTBytes is a constant representing the byte length of ciphertexts in Kyber-512
    public final static int KYBER_512CT_BYTES = PARAMS_POLYVEC_COMPRESSED_BYTES_K512 + PARAMS_POLY_COMPRESSED_BYTES_K512;

    // Kyber768CTBytes is a constant representing the byte length of ciphertexts in Kyber-768
    public final static int KYBER_768CT_BYTES = PARAMS_POLYVEC_COMPRESSED_BYTES_K768 + PARAMS_POLY_COMPRESSED_BYTES_K768;

    // Kyber1024CTBytes is a constant representing the byte length of ciphertexts in Kyber-1024
    public final static int KYBER_1024CT_BYTES = PARAMS_POLYVEC_COMPRESSED_BYTES_K1024 + PARAMS_POLY_COMPRESSED_BYTES_K1024;

    // KyberEncoded512CTBytes is a constant representing the byte length of Encoded ciphertexts in Kyber-512
    public final static int KYBER_ENCODED_512CT_BYTES = 935;

    // KyberEncoded768CTBytes is a constant representing the byte length of Encoded ciphertexts in Kyber-768
    public final static int KYBER_ENCODED_768CT_BYTES = 1255;

    // KyberEncoded1024CTBytes is a constant representing the byte length of Encoded ciphertexts in Kyber-1024
    public final static int KYBER_ENCODED_1024CT_BYTES = 1735;

    // KyberSSBytes is a constant representing the byte length of shared secrets in Kyber
    public final static int KYBER_SS_BYTES = 32;

    // KyberEncodedSSBytes is a constant representing the byte length of encoded shared secrets in Kyber
    public final static int KYBER_ENCODED_SS_BYTES = 193;

    // Default p value
    //public final static BigInteger DEFAULT_P = new BigInteger("fca682ce8e12caba26efccf7110e526db078b05edecbcd1eb4a208f3ae1617ae01f35b91a47e6df63413c5e12ed0899bcd132acd50d99151bdc43ee737592e17", 16);

    // Default g value
    //public final static BigInteger DEFAULT_G = new BigInteger("678471b27a9cf44ee91a49c5147db1a9aaf244f05a434d6486931d2d14271b9e35030b71fd73da179069b32e2935630e1c2062354d0da20a6c416e50be794ca4", 16);
}
