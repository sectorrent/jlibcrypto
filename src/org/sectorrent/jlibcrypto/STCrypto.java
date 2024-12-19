package org.sectorrent.jlibcrypto;

import java.security.Provider;

public class STCrypto extends Provider {

    public STCrypto(){
        super("SPHINCSPLUS", 1.0, "Quantum Proof Cryptographic Provider");

        // Register SPHINCS+ Signature
        put("Signature.SPHINCSPLUS", "org.sectorrent.jlibcrypto.sphincs.SphincsPlusSignature");

        // Register SPHINCS+ KeyPairGenerator
        put("KeyPairGenerator.SPHINCSPLUS", "org.sectorrent.jlibcrypto.sphincs.SphincsPlusKeyPairGenerator");

        put("MessageDigest.CRC32C", "org.sectorrent.jlibcrypto.hash.CRC32c");
        put("MessageDigest.SHA256", "org.sectorrent.jlibcrypto.hash.SHA256x");
    }
}
