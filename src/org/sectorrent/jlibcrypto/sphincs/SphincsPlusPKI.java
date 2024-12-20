package org.sectorrent.jlibcrypto.sphincs;

public class SphincsPlusPKI {

    private SphincsPlusPublicKey publicKey;
    private SphincsPlusPrivateKey privateKey;

    public SphincsPlusPKI(){
    }

    public SphincsPlusPKI(SphincsPlusPublicKey publicKey, SphincsPlusPrivateKey privateKey){
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public void setPublicKey(SphincsPlusPublicKey publicKey){
        this.publicKey = publicKey;
    }

    public SphincsPlusPublicKey getPublicKey(){
        return publicKey;
    }

    public void setPrivateKey(SphincsPlusPrivateKey privateKey){
        this.privateKey = privateKey;
    }

    public SphincsPlusPrivateKey getPrivateKey(){
        return privateKey;
    }
}
