package org.sectorrent.jlibcrypto;

import java.security.Provider;

public class STCrypto extends Provider {

    public STCrypto() {
        super("STCryptoProvider", 1.0, "Quantum Proof Cryptographic Provider");

        // Register SPHINCS+ Signature
        put("Signature.SPHINCSPLUS", "org.sectorrent.jlibcrypto.sphincs.SphincsPlusSignature");

        // Register SPHINCS+ KeyPairGenerator
        put("KeyPairGenerator.SPHINCSPLUS", "org.sectorrent.jlibcrypto.sphincs.SphincsPlusKeyPairGenerator");

        //put("MessageDigest.MyHash", "");
    }
}
