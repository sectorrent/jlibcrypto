package org.sectorrent.jlibcrypto.hash;

import java.security.MessageDigest;
import java.util.Arrays;

public class SHA3_256 extends MessageDigest {

    private static final int[] ROTATION_CONSTANTS = {
            0, 1, 62, 28, 27,
            36, 44, 6, 55, 20,
            3, 10, 43, 25, 39,
            41, 45, 15, 21, 8,
            18, 2, 61, 56, 14
    };

    private static final long[] ROUND_CONSTANTS = {
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808AL, 0x8000000080008000L,
            0x000000000000808BL, 0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L,
            0x000000000000008AL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000AL,
            0x000000008000808BL, 0x800000000000008BL, 0x8000000000008089L, 0x8000000000008003L,
            0x8000000000008002L, 0x8000000000000080L, 0x000000000000800AL, 0x800000008000000AL,
            0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };

    private static final int BITRATE = 1088; // 1600 - 2*256
    private static final int STATE_SIZE = 200; // 1600 bits = 200 bytes
    private static final int OUTPUT_LENGTH = 32; // 256 bits = 32 bytes
    private static final byte DOMAIN_PADDING = 0x06; // SHA3 domain separation padding

    private byte[] state = new byte[STATE_SIZE];
    private int bitsInQueue = 0;

    public SHA3_256(){
        super("SHA3-256");
        engineReset();
    }

    @Override
    protected void engineUpdate(byte input){
        engineUpdate(new byte[]{input}, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len){
        int byteOffset = bitsInQueue/8;
        int rateBytes = BITRATE/8;

        while(len > 0){
            int bytesToAbsorb = Math.min(len, rateBytes - byteOffset);

            for(int i = 0; i < bytesToAbsorb; i++){
                state[byteOffset+i] ^= input[offset+i];
            }
            byteOffset += bytesToAbsorb;
            offset += bytesToAbsorb;
            len -= bytesToAbsorb;

            if(byteOffset == rateBytes){
                keccakF(state);
                byteOffset = 0;
            }
        }

        bitsInQueue = byteOffset*8;
    }

    @Override
    protected byte[] engineDigest(){
        state[bitsInQueue/8] ^= DOMAIN_PADDING;
        state[(BITRATE-1)/8] ^= 0x80;
        keccakF(state);

        byte[] result = new byte[OUTPUT_LENGTH];
        int outputBytes = 0;
        int rateBytes = BITRATE/8;

        while(outputBytes < OUTPUT_LENGTH){
            System.arraycopy(state, 0, result, outputBytes, Math.min(rateBytes, OUTPUT_LENGTH-outputBytes));
            outputBytes += rateBytes;

            if(outputBytes < OUTPUT_LENGTH){
                keccakF(state);
            }
        }

        engineReset();
        return result;
    }

    @Override
    protected void engineReset(){
        Arrays.fill(state, (byte) 0);
        bitsInQueue = 0;
    }

    private void keccakF(byte[] state){
        long[] lanes = toLanes(state);

        for(int round = 0; round < 24; round++){
            long[] C = new long[5];
            for(int x = 0; x < 5; x++){
                C[x] = lanes[x] ^ lanes[x + 5] ^ lanes[x + 10] ^ lanes[x + 15] ^ lanes[x + 20];
            }

            long[] D = new long[5];
            for(int x = 0; x < 5; x++){
                D[x] = C[(x + 4) % 5] ^ Long.rotateLeft(C[(x + 1) % 5], 1);
            }

            for(int x = 0; x < 5; x++){
                for(int y = 0; y < 5; y++){
                    lanes[x + 5 * y] ^= D[x];
                }
            }

            // ρ (rho) and π (pi) steps
            long[] B = new long[25];
            for(int x = 0; x < 5; x++){
                for(int y = 0; y < 5; y++){
                    int index = x + 5 * y;
                    int newX = y;
                    int newY = (2 * x + 3 * y) % 5;
                    int newIndex = newX + 5 * newY;
                    B[newIndex] = Long.rotateLeft(lanes[index], ROTATION_CONSTANTS[index]);
                }
            }

            // χ (chi) step
            for(int x = 0; x < 5; x++){
                for(int y = 0; y < 5; y++){
                    int index = x + 5 * y;
                    lanes[index] = B[index] ^ (~B[(x + 1) % 5 + 5 * y] & B[(x + 2) % 5 + 5 * y]);
                }
            }

            // ι (iota) step
            lanes[0] ^= ROUND_CONSTANTS[round];
        }

        fromLanes(state, lanes);
    }

    private long[] toLanes(byte[] state){
        long[] lanes = new long[25];

        for(int i = 0; i < lanes.length; i++){
            lanes[i] = 0;
            for(int j = 0; j < 8; j++){
                lanes[i] |= (state[i * 8 + j] & 0xFFL) << (8 * j);
            }
        }
        return lanes;
    }

    private void fromLanes(byte[] state, long[] lanes){
        for(int i = 0; i < lanes.length; i++){
            for(int j = 0; j < 8; j++){
                state[i * 8 + j] = (byte) ((lanes[i] >>> (8 * j)) & 0xFF);
            }
        }
    }
}
