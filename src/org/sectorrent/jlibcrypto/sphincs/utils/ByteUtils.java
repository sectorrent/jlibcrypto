package org.sectorrent.jlibcrypto.sphincs.utils;

import java.util.Arrays;

import static org.sectorrent.jlibcrypto.sphincs.SphincsPlusParams.*;

public class ByteUtils {

    public static void setByte(int[] out, int byteOffset, byte val){
        int index = byteOffset/4;
        int mod = byteOffset%4;
        int prior = out[index];
        out[index] = (prior & ~(0xFF << (mod*8))) | ((val & 0xFF) << (mod*8));
    }

    public static byte getByte(int[] in, int byteOffset){
        int index = byteOffset/4;
        int mod = byteOffset%4;
        return (byte) (in[index] >> (mod*8));
    }

    public static byte[] intsToBytes(int[] in, int bytes){
        int intCount = (bytes+3)/4;
        byte[] res = new byte[bytes+4];

        for(int i = 0; i < intCount; i++){
            res[i*4] = (byte)in[i];
            res[i*4+1] = (byte)(in[i] >> 8);
            res[i*4+2] = (byte)(in[i] >> 16);
            res[i*4+3] = (byte)(in[i] >> 24);
        }

        return Arrays.copyOfRange(res, 0, bytes);
    }

    public static void u32ToBytes(byte[] out, int outOffset, int in){
        out[outOffset+0] = (byte)(in >> 24);
        out[outOffset+1] = (byte)(in >> 16);
        out[outOffset+2] = (byte)(in >> 8);
        out[outOffset+3] = (byte)in;
    }

    public static void ullToBytes(byte[] out, int in){
        for(int i = out.length-1; i >= 0; i--){
            out[i] = (byte)in;
            in = in >> 8;
        }
    }

    public static long bytesToUll(byte[] in, int inOffset, int inlen){
        long retval = 0;

        for(int i = 0; i < inlen; i++){
            retval |= (in[inOffset+i] & 0xFFL) << (8*(inlen-1-i));
        }
        return retval;
    }
}
