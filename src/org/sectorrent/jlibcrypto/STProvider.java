package org.sectorrent.jlibcrypto;

import java.security.Provider;

public class STProvider extends Provider {

    public STProvider(){
        super("STProvider", 1.0, "SecTorrent Quantum Proof Cryptographic Provider");

        put("Signature.SphincsPlus", "org.sectorrent.jlibcrypto.sphincs.SphincsPlusSignature");
        put("KeyPairGenerator.SphincsPlus", "org.sectorrent.jlibcrypto.sphincs.SphincsPlusKeyPairGenerator");

        put("MessageDigest.SHA-256", "org.sectorrent.jlibcrypto.hash.SHA256");
        put("MessageDigest.CRC32C", "org.sectorrent.jlibcrypto.hash.CRC32c");
    }
}
