package org.sectorrent.jlibcrypto.hash;

import java.security.MessageDigest;

public class SHA256 extends MessageDigest {

    private static final int BLOCK_SIZE = 64;

    private static final int[] k = {
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

    private static final int[] w = new int[64];

    private int[] h = {
            0x6a09e667,
            0xbb67ae85,
            0x3c6ef372,
            0xa54ff53a,
            0x510e527f,
            0x9b05688c,
            0x1f83d9ab,
            0x5be0cd19
    };

    private byte[] buffer = new byte[BLOCK_SIZE];
    private int initialCount = 0, count = 0;

    public SHA256(){
        super("SHA-256");
    }

    public SHA256(byte[] state, int count){
        super("SHA-256");
        this.h[0] = parseInt(state, 0);
        this.h[1] = parseInt(state, 4);
        this.h[2] = parseInt(state, 8);
        this.h[3] = parseInt(state, 12);
        this.h[4] = parseInt(state, 16);
        this.h[5] = parseInt(state, 20);
        this.h[6] = parseInt(state, 24);
        this.h[7] = parseInt(state, 28);
        this.initialCount = count;
        this.count = count;
    }

    @Override
    protected void engineUpdate(byte input){
        int i = (int) (count%BLOCK_SIZE);
        count++;
        buffer[i] = input;

        if(i == (BLOCK_SIZE-1)){
            transform(buffer, 0);
        }
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len){
        int n = (int) (count%BLOCK_SIZE);
        count += len;
        int partLen = BLOCK_SIZE-n;
        int i = 0;

        if(len >= partLen){
            System.arraycopy(input, offset, buffer, n, partLen);
            transform(buffer, 0);
            for(i = partLen; i+BLOCK_SIZE-1 < len; i += BLOCK_SIZE){
                transform(input, offset+i);
            }

            n = 0;
        }

        if(i < len){
            System.arraycopy(input, offset+i, buffer, n, len-i);
        }
    }

    @Override
    protected byte[] engineDigest(){
        byte[] tail = padBuffer();
        engineUpdate(tail, 0, tail.length);
        byte[] result = getResult();
        engineReset();

        return result;
    }

    @Override
    protected void engineReset(){
        buffer = new byte[BLOCK_SIZE];
        h = new int[]{
                0x6a09e667,
                0xbb67ae85,
                0x3c6ef372,
                0xa54ff53a,
                0x510e527f,
                0x9b05688c,
                0x1f83d9ab,
                0x5be0cd19
        };
        count = initialCount;
    }

    private void completeBlock(){
        byte[] tail = padBuffer();
        update(tail, 0, tail.length);
    }

    public byte[] getState(){
        byte[] res = new byte[40];
        storeInt(res, 0, h[0]);
        storeInt(res, 4, h[1]);
        storeInt(res, 8, h[2]);
        storeInt(res, 12, h[3]);
        storeInt(res, 16, h[4]);
        storeInt(res, 20, h[5]);
        storeInt(res, 24, h[6]);
        storeInt(res, 28, h[7]);
        storeBigendianLong(res, 32, count);

        return res;
    }

    private int parseInt(byte[] data, int offset){
        return data[offset+3] & 0xFF |
                ((data[offset+2] & 0xFF) << 8) |
                ((data[offset + 1] & 0xFF) << 16) |
                ((data[offset+0] & 0xFF) << 24);
    }

    private void storeInt(byte[] data, int offset, int val){
        data[offset+0] = (byte)(val >> 24);
        data[offset+1] = (byte)(val >> 16);
        data[offset+2] = (byte)(val >> 8);
        data[offset+3] = (byte) val;
    }

    private static void storeBigendianLong(byte[] data, int offset, long val){
        for(int i=0; i < 8; i++){
            data[offset + i] = (byte) (val >> (56 - i*8));
        }
    }

    public static final int[] G(int hh0, int hh1, int hh2, int hh3, int hh4, int hh5, int hh6, int hh7, byte[] in, int offset){
        return sha(hh0, hh1, hh2, hh3, hh4, hh5, hh6, hh7, in, offset);
    }

    private void transform(byte[] in, int offset){
        int[] result = sha(h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], in, offset);
        h[0] = result[0];
        h[1] = result[1];
        h[2] = result[2];
        h[3] = result[3];
        h[4] = result[4];
        h[5] = result[5];
        h[6] = result[6];
        h[7] = result[7];
    }

    private byte[] padBuffer(){
        int n = (int)(count % BLOCK_SIZE);
        int padding = (n < 56) ? (56-n) : (120 - n);
        byte[] result = new byte[padding+8];

        result[0] = (byte) 0x80;

        long bits = count << 3;
        result[padding++] = (byte)(bits >>> 56);
        result[padding++] = (byte)(bits >>> 48);
        result[padding++] = (byte)(bits >>> 40);
        result[padding++] = (byte)(bits >>> 32);
        result[padding++] = (byte)(bits >>> 24);
        result[padding++] = (byte)(bits >>> 16);
        result[padding++] = (byte)(bits >>> 8);
        result[padding] = (byte) bits;
        return result;
    }

    private byte[] getResult(){
        return new byte[]{
                (byte)(h[0] >>> 24), (byte)(h[0] >>> 16), (byte)(h[0] >>> 8), (byte) h[0],
                (byte)(h[1] >>> 24), (byte)(h[1] >>> 16), (byte)(h[1] >>> 8), (byte) h[1],
                (byte)(h[2] >>> 24), (byte)(h[2] >>> 16), (byte)(h[2] >>> 8), (byte) h[2],
                (byte)(h[3] >>> 24), (byte)(h[3] >>> 16), (byte)(h[3] >>> 8), (byte) h[3],
                (byte)(h[4] >>> 24), (byte)(h[4] >>> 16), (byte)(h[4] >>> 8), (byte) h[4],
                (byte)(h[5] >>> 24), (byte)(h[5] >>> 16), (byte)(h[5] >>> 8), (byte) h[5],
                (byte)(h[6] >>> 24), (byte)(h[6] >>> 16), (byte)(h[6] >>> 8), (byte) h[6],
                (byte)(h[7] >>> 24), (byte)(h[7] >>> 16), (byte)(h[7] >>> 8), (byte) h[7]
        };
    }

    private static synchronized int[] sha(int hh0, int hh1, int hh2, int hh3, int hh4, int hh5, int hh6, int hh7, byte[] in, int offset){
        int A = hh0;
        int B = hh1;
        int C = hh2;
        int D = hh3;
        int E = hh4;
        int F = hh5;
        int G = hh6;
        int H = hh7;
        int r, T, T2;

        for(r = 0; r < 16; r++){
            w[r] = (in[offset++]         << 24
                    | (in[offset++] & 0xFF) << 16
                    | (in[offset++] & 0xFF) << 8
                    | (in[offset++] & 0xFF));
        }

        for(r = 16; r < 64; r++){
            T =  w[r -  2];
            T2 = w[r - 15];
            w[r] = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10))
                    + w[r - 7]
                    + (((T2 >>> 7) | (T2 << 25))
                    ^ ((T2 >>> 18) | (T2 << 14))
                    ^ (T2 >>> 3)) + w[r - 16]);
        }

        for (r = 0; r < 64; r++){
            T = (H
                    + (((E >>> 6) | (E << 26))
                    ^ ((E >>> 11) | (E << 21))
                    ^ ((E >>> 25) | (E << 7)))
                    + ((E & F) ^ (~E & G)) + k[r] + w[r]);
            T2 = ((((A >>> 2) | (A << 30))
                    ^ ((A >>> 13) | (A << 19))
                    ^ ((A >>> 22) | (A << 10))) + ((A & B) ^ (A & C) ^ (B & C)));
            H = G;
            G = F;
            F = E;
            E = D + T;
            D = C;
            C = B;
            B = A;
            A = T + T2;
        }

        return new int[]{
                hh0 + A,
                hh1 + B,
                hh2 + C,
                hh3 + D,
                hh4 + E,
                hh5 + F,
                hh6 + G,
                hh7 + H
        };
    }
}
