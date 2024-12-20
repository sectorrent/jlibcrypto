package org.sectorrent.jlibcrypto.kyber;

public class KyberPKI {

    private KyberPublicKey publicKey;
    private KyberPrivateKey privateKey;

    public KyberPKI(){
    }

    public KyberPKI(KyberPublicKey publicKey, KyberPrivateKey privateKey){
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public void setPublicKey(KyberPublicKey publicKey){
        this.publicKey = publicKey;
    }

    public KyberPublicKey getPublicKey(){
        return publicKey;
    }

    public void setPrivateKey(KyberPrivateKey privateKey){
        this.privateKey = privateKey;
    }

    public KyberPrivateKey getPrivateKey(){
        return privateKey;
    }
}
