package org.sectorrent.jlibcrypto;

import java.security.Provider;

public class STProvider extends Provider {

    public STProvider(){
        super("STProvider", 1.0, "SecTorrent Quantum Proof Cryptographic Provider");

        put("Signature.SphincsPlus", "org.sectorrent.jlibcrypto.sphincs.SphincsPlusSignature");
        put("KeyPairGenerator.SphincsPlus", "org.sectorrent.jlibcrypto.sphincs.SphincsPlusKeyPairGenerator");

        put("KeyPairGenerator.Kyber512", "org.sectorrent.jlibcrypto.kyber.Kyber512KeyPairGenerator");
        put("KeyPairGenerator.Kyber768", "org.sectorrent.jlibcrypto.kyber.Kyber768KeyPairGenerator");
        put("KeyPairGenerator.Kyber1024", "org.sectorrent.jlibcrypto.kyber.Kyber1024KeyPairGenerator");

        put("MessageDigest.SHA2-256", "org.sectorrent.jlibcrypto.hash.SHA2_256");
        put("MessageDigest.SHA3-256", "org.sectorrent.jlibcrypto.hash.SHA3_256");
        put("MessageDigest.SHA3-512", "org.sectorrent.jlibcrypto.hash.SHA3_512");
        put("MessageDigest.CRC32C", "org.sectorrent.jlibcrypto.hash.CRC32c");
    }
}
