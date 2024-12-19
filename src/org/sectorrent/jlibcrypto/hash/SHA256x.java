package org.sectorrent.jlibcrypto.hash;

import java.security.MessageDigest;
import java.util.Arrays;

public class SHA256x extends MessageDigest {

    private byte[] message;

    public SHA256x(){
        super("SHA256");
    }

    @Override
    protected void engineUpdate(byte input){
        engineUpdate(new byte[]{ input }, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len){
        if(offset > len){
            throw new IllegalArgumentException("Offset is greater than length");
        }

        if(message == null){
            message = new byte[len-offset];
            System.arraycopy(input, offset, message, 0, message.length);
            return;
        }

        byte[] m = new byte[message.length+len-offset];
        System.arraycopy(message, 0, m, 0, m.length);
        System.arraycopy(input, offset, m, message.length, len-offset);
        message = m;
    }

    @Override
    protected byte[] engineDigest(){
        byte[] padded = padMessage(message);

        int[] hs = Arrays.copyOf(HS, 8);

        for(int i = 0; i < padded.length/64; ++i){
            int[] registers = Arrays.copyOf(hs, 8);
            System.arraycopy(padded, 64*i, block, 0, 64);

            setupWords();

            for(int j = 0; j < 64; ++j){
                iterate(registers, words, j);
            }

            for(int j = 0; j < 8; ++j){
                hs[j] += registers[j];
            }
        }

        byte[] hash = new byte[32];

        for(int i = 0; i < 8; i++){
            System.arraycopy(intToBytes(hs[i]), 0, hash, 4 * i, 4);
        }

        return hash;
    }

    @Override
    protected void engineReset(){
        message = null;
    }

    private static final int[] HS = {
            0x6a09e667,
            0xbb67ae85,
            0x3c6ef372,
            0xa54ff53a,
            0x510e527f,
            0x9b05688c,
            0x1f83d9ab,
            0x5be0cd19
    };

    private static final int[] KS = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    private final byte[] block = new byte[64];

    private final int[] words = new int[64];

    private void setupWords(){
        for(int j = 0; j < 16; j++){
            words[j] = 0;
            for(int m = 0; m < 4; m++){
                words[j] |= ((block[j*4+m] & 0x000000FF) << (24-m*8));
            }
        }

        for(int j = 16; j < 64; ++j){
            int s0 = Integer.rotateRight(words[j-15], 7) ^
                    Integer.rotateRight(words[j-15], 18) ^
                    (words[j-15] >>> 3);

            int s1 = Integer.rotateRight(words[j-2], 17) ^
                    Integer.rotateRight(words[j-2], 19) ^
                    (words[j-2] >>> 10);

            words[j] = words[j-16]+s0+words[j-7] + s1;
        }
    }

    private static void iterate(int[] registers, int[] words, int j){
        int S0 = Integer.rotateRight(registers[0], 2) ^
                Integer.rotateRight(registers[0], 13) ^
                Integer.rotateRight(registers[0], 22);

        int maj = (registers[0] & registers[1]) ^ (registers[0] & registers[2]) ^ (registers[1] & registers[2]);

        int temp2 = S0 + maj;

        int S1 = Integer.rotateRight(registers[4], 6) ^
                Integer.rotateRight(registers[4], 11) ^
                Integer.rotateRight(registers[4], 25);

        int ch = (registers[4] & registers[5]) ^ (~registers[4] & registers[6]);

        int temp1 = registers[7] + S1 + ch + KS[j] + words[j];

        registers[7] = registers[6];
        registers[6] = registers[5];
        registers[5] = registers[4];
        registers[4] = registers[3]+temp1;
        registers[3] = registers[2];
        registers[2] = registers[1];
        registers[1] = registers[0];
        registers[0] = temp1+temp2;
    }

    private byte[] padMessage(byte[] data){
        int length = data.length;
        int tail = length%64;
        int padding;

        if((64-tail >= 9)){
            padding = 64-tail;
        }else{
            padding = 128-tail;
        }

        byte[] pad = new byte[padding];
        pad[0] = (byte) 0x80;
        long bits = length*8;

        for(int i = 0; i < 8; i++){
            pad[pad.length-1-i] = (byte) ((bits >>> (8*i)) & 0xFF);
        }

        byte[] output = new byte[length + padding];
        System.arraycopy(data, 0, output, 0, length);
        System.arraycopy(pad, 0, output, length, pad.length);

        return output;
    }

    public byte[] intToBytes(int i){
        byte[] b = new byte[4];
        for(int c = 0; c < 4; c++){
            b[c] = (byte) ((i >>> (56-8*c)) & 0xff);
        }
        return b;
    }
}
