package org.sectorrent.jlibcrypto.hash;

public class SHAKE256 {

    private static final long[] RC = { // Round constants
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL, 0x8000000080008000L, 0x000000000000808bL,
            0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL, 0x0000000000000088L,
            0x0000000080008009L, 0x000000008000000aL, 0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
            0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L, 0x000000000000800aL, 0x800000008000000aL,
            0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };

    private static final int[][] R = { // Rotation offsets
            {0, 36, 3, 41, 18},
            {1, 44, 10, 45, 2},
            {62, 6, 43, 15, 61},
            {28, 55, 25, 21, 56},
            {27, 20, 39, 8, 14}
    };

    public static byte[] getHash(int hashByteLength, byte[] message) {
        return getHash(hashByteLength, message, 0, message.length);
    }

    public static byte[] getHash(int hashByteLength, byte[] message, int messageStart, int messageLength) {
        if (hashByteLength < 2) {
            throw new UnsupportedOperationException("Too small hash length, require hashByteLength >= 2");
        }
        if (hashByteLength > 8192) {
            throw new UnsupportedOperationException("Too big hash length, require hashByteLength <= 8192");
        }

        long[][] a = new long[5][5]; // State array
        long[][] b = new long[5][5]; // Intermediate variable
        long[] c = new long[5]; // Intermediate variable
        long[] d = new long[5]; // Intermediate variable
        long[] block = new long[17]; // 1088-bit block (17 * 64 bits)
        int blockPos = 0;
        int messagePos = messageStart;
        int stop = messageStart + messageLength - 7;

        while (messagePos < stop) {
            block[blockPos++] = getWord(message, messagePos);
            messagePos += 8;
            if (blockPos == 17) {
                blockPos = 0;
                hashBlock(block, a, b, c, d);
            }
        }

        byte[] buffer = new byte[8];
        int bufferPos = 0;

        while (messagePos < messageStart + messageLength) {
            buffer[bufferPos++] = message[messagePos++];
        }

        buffer[bufferPos] = (byte) 0x1F; // Domain separator for SHAKE256
        if (blockPos == 16) {
            buffer[7] |= 0x80;
        } else {
            block[blockPos++] = getWord(buffer, 0);
            while (blockPos < 16) {
                block[blockPos++] = 0L;
            }
            buffer = new byte[8];
            buffer[7] |= 0x80;
        }
        block[blockPos] = getWord(buffer, 0);
        hashBlock(block, a, b, c, d);

        byte[] hash = new byte[hashByteLength];
        int hashPos = 0;

        while (true) {
            for (int y = 0; y < 5; y++) {
                for (int x = 0; x < 5; x++) {
                    if (x + 5 * y < 17) {
                        long word = a[x][y];
                        for (int i = 0; i < 8; i++) {
                            hash[hashPos++] = (byte) word;
                            if (hashPos == hashByteLength) {
                                return hash;
                            }
                            word >>= 8;
                        }
                    }
                }
            }
            f(a, b, c, d);
        }
    }

    private static long getWord(byte[] bytes, int bytesStart) {
        return (bytes[bytesStart] & 0xFFL) |
                (bytes[bytesStart + 1] & 0xFFL) << 8 |
                (bytes[bytesStart + 2] & 0xFFL) << 16 |
                (bytes[bytesStart + 3] & 0xFFL) << 24 |
                (bytes[bytesStart + 4] & 0xFFL) << 32 |
                (bytes[bytesStart + 5] & 0xFFL) << 40 |
                (bytes[bytesStart + 6] & 0xFFL) << 48 |
                (bytes[bytesStart + 7] & 0xFFL) << 56;
    }

    private static void hashBlock(long[] block, long[][] a, long[][] b, long[] c, long[] d) {
        for (int y = 0; y < 5; y++) {
            for (int x = 0; x < 5; x++) {
                int index = x + 5 * y;
                if (index >= block.length){
                    break; // Ensure we don't access out-of-bounds
                }
                a[x][y] ^= block[index];
            }
        }
        f(a, b, c, d);
    }

    private static void f(long[][] a, long[][] b, long[] c, long[] d) {
        for (int i = 0; i < 24; i++) {
            for (int x = 0; x < 5; x++) {
                c[x] = a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4];
            }
            for (int x = 0; x < 5; x++) {
                d[x] = c[(x + 4) % 5] ^ rot(c[(x + 1) % 5], 1);
            }
            for (int y = 0; y < 5; y++) {
                for (int x = 0; x < 5; x++) {
                    a[x][y] ^= d[x];
                }
            }
            for (int y = 0; y < 5; y++) {
                for (int x = 0; x < 5; x++) {
                    b[y][(2 * x + 3 * y) % 5] = rot(a[x][y], R[x][y]);
                }
            }
            for (int y = 0; y < 5; y++) {
                for (int x = 0; x < 5; x++) {
                    a[x][y] = b[x][y] ^ (~b[(x + 1) % 5][y] & b[(x + 2) % 5][y]);
                }
            }
            a[0][0] ^= RC[i];
        }
    }

    private static long rot(long x, int s) {
        return (x << s) | (x >>> (64 - s));
    }
}
