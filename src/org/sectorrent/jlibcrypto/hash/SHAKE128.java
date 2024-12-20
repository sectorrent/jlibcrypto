package org.sectorrent.jlibcrypto.hash;

import java.util.Arrays;

public class SHAKE128 {

    // Constants for SHAKE128
    private static final int RATE = 168; // Block size for SHAKE128 in bytes
    private static final int CAPACITY = 32; // Capacity size for SHAKE128 in bytes
    private static final int STATE_SIZE = 200; // Keccak state size in bytes
    private static final int BITRATE = RATE * 8;

    // Keccak permutation
    private static void keccakPermutation(byte[] state) {
        final long[] RC = {
                0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL, 0x8000000080008000L,
                0x000000000000808bL, 0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L,
                0x000000000000008aL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
                0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L, 0x8000000000008003L,
                0x8000000000008002L, 0x8000000000000080L, 0x000000000000800aL, 0x800000008000000aL,
                0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
        };

        // Convert state from bytes to 64-bit words
        long[] lanes = new long[25];
        for (int i = 0; i < lanes.length; i++) {
            lanes[i] = 0;
            for (int j = 0; j < 8; j++) {
                lanes[i] |= ((long) state[i * 8 + j] & 0xFF) << (8 * j);
            }
        }

        // 24 Rounds of Keccak-f[1600]
        for (int round = 0; round < 24; round++) {
            // θ step
            long[] C = new long[5];
            for (int x = 0; x < 5; x++) {
                C[x] = lanes[x] ^ lanes[x + 5] ^ lanes[x + 10] ^ lanes[x + 15] ^ lanes[x + 20];
            }
            long[] D = new long[5];
            for (int x = 0; x < 5; x++) {
                D[x] = C[(x + 4) % 5] ^ Long.rotateLeft(C[(x + 1) % 5], 1);
            }
            for (int i = 0; i < 25; i++) {
                lanes[i] ^= D[i % 5];
            }

            // ρ and π steps
            long[] B = new long[25];
            for (int x = 0; x < 5; x++) {
                for (int y = 0; y < 5; y++) {
                    int index = x + 5 * y;
                    int newX = y;
                    int newY = (2 * x + 3 * y) % 5;
                    int newIndex = newX + 5 * newY;
                    B[newIndex] = Long.rotateLeft(lanes[index], (int) ((x + 3 * y) % 64));
                }
            }

            // χ step
            for (int x = 0; x < 5; x++) {
                for (int y = 0; y < 5; y++) {
                    int index = x + 5 * y;
                    lanes[index] = B[index] ^ ((~B[x + 5 * ((y + 1) % 5)]) & B[x + 5 * ((y + 2) % 5)]);
                }
            }

            // ι step
            lanes[0] ^= RC[round];
        }

        // Convert state back to bytes
        for (int i = 0; i < lanes.length; i++) {
            for (int j = 0; j < 8; j++) {
                state[i * 8 + j] = (byte) ((lanes[i] >>> (8 * j)) & 0xFF);
            }
        }
    }

    // Absorb phase: Input data into the state
    private static void absorb(byte[] state, byte[] input) {
        int inputOffset = 0;

        while (inputOffset < input.length) {
            int blockSize = Math.min(RATE, input.length - inputOffset);
            for (int i = 0; i < blockSize; i++) {
                state[i] ^= input[inputOffset + i];
            }
            inputOffset += blockSize;
            keccakPermutation(state); // Permutation after each block
        }
    }

    // Squeeze phase: Output data from the state
    private static byte[] squeeze(byte[] state, int outputLength) {
        byte[] output = new byte[outputLength];
        int outputOffset = 0;

        while (outputOffset < outputLength) {
            int blockSize = Math.min(RATE, outputLength - outputOffset);
            System.arraycopy(state, 0, output, outputOffset, blockSize);
            outputOffset += blockSize;
            if (outputOffset < outputLength) {
                keccakPermutation(state); // Permutation if more output is needed
            }
        }
        return output;
    }

    // SHAKE128 XOF implementation
    public static byte[] shake128(byte[] input, int outputLength) {
        // Initialize state
        byte[] state = new byte[STATE_SIZE];
        Arrays.fill(state, (byte) 0);

        // Absorb phase
        absorb(state, input);

        // Padding for XOF
        //state[input.length] ^= 0x1F; // Domain separation for SHAKE
        //state[RATE - 1] ^= (byte) 0x80;
        int lastIndex = input.length % RATE;
        state[lastIndex] ^= 0x1F;
        state[RATE - 1] ^= (byte) 0x80;

        // Permutation before squeezing
        keccakPermutation(state);

        // Squeeze phase
        return squeeze(state, outputLength);
    }
}
