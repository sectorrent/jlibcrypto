package org.sectorrent.jlibcrypto;

import java.security.Provider;

public class STCrypto extends Provider {

    public STCrypto(){
        super("STCrypto", 1.0, "Quantum Proof Cryptographic Provider");

        put("Signature.SPHINCSPLUS", "org.sectorrent.jlibcrypto.sphincs.SphincsPlusSignature");
        put("KeyPairGenerator.SPHINCSPLUS", "org.sectorrent.jlibcrypto.sphincs.SphincsPlusKeyPairGenerator");

        put("MessageDigest.SHA-256", "org.sectorrent.jlibcrypto.hash.SHA256");
        put("MessageDigest.CRC32C", "org.sectorrent.jlibcrypto.hash.CRC32c");
    }
}
