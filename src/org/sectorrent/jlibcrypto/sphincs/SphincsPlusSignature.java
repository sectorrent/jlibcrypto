package org.sectorrent.jlibcrypto.sphincs;

import java.security.*;

public class SphincsPlusSignature extends SignatureSpi {

    private SphincsPlus sphincs;
    private boolean forSigning;

    @Override
    protected void engineInitVerify(PublicKey publicKey)throws InvalidKeyException {
        if(!(publicKey instanceof SphincsPlusPublicKey)){
            throw new InvalidKeyException("Invalid public key for SPHINCS+");
        }

        sphincs = new SphincsPlus(((SphincsPlusPublicKey) publicKey).getPublicKeyBytes());
        forSigning = false;
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey)throws InvalidKeyException {
        if(!(privateKey instanceof SphincsPlusPrivateKey)){
            throw new InvalidKeyException("Invalid private key for SPHINCS+");
        }

        sphincs = new SphincsPlus(((SphincsPlusPrivateKey) privateKey).getPrivateKeyBytes());
        forSigning = true;
    }

    @Override
    protected void engineUpdate(byte b)throws SignatureException {
        sphincs.update(b);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len)throws SignatureException {
        sphincs.update(b, off, len);
    }

    @Override
    protected byte[] engineSign()throws SignatureException {
        if(!forSigning){
            throw new SignatureException("Engine not initialized for signing");
        }

        return sphincs.sign();
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes)throws SignatureException {
        if(forSigning){
            throw new SignatureException("Engine not initialized for verification");
        }

        return sphincs.verify(sigBytes);
    }

    @Override
    protected void engineSetParameter(String param, Object value)throws InvalidParameterException {
        throw new UnsupportedOperationException("SPHINCS+ does not support parameters");
    }

    @Override
    protected Object engineGetParameter(String param)throws InvalidParameterException {
        throw new UnsupportedOperationException("SPHINCS+ does not support parameters");
    }
}
