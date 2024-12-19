package org.sectorrent.jlibcrypto.sphincs.old;

public class LeafInfoX1 {

    private byte[] wotsSig;
    private int wotsSigOffset = 0;
    private int wotsSignLeaf;
    private int[] wotsSteps;
    private int[] leafAddr = new int[8];
    private int[] pkAddr = new int[8];

    public LeafInfoX1(){
    }

    public void setWotsSig(byte[] wotsSig){
        this.wotsSig = wotsSig;
    }

    public byte[] getWotsSig(){
        return wotsSig;
    }

    public void setWotsSigOffset(int wotsSigOffset){
        this.wotsSigOffset = wotsSigOffset;
    }

    public int getWotsSigOffset(){
        return wotsSigOffset;
    }

    public void setWotsSignLeaf(int wotsSignLeaf){
        this.wotsSignLeaf = wotsSignLeaf;
    }

    public int getWotsSignLeaf(){
        return wotsSignLeaf;
    }

    public void setWotsSteps(int[] wotsSteps){
        this.wotsSteps = wotsSteps;
    }

    public int[] getWotsSteps(){
        return wotsSteps;
    }

    public void setLeafAddr(int[] leafAddr){
        this.leafAddr = leafAddr;
    }

    public int[] getLeafAddr(){
        return leafAddr;
    }

    public void setPkAddr(int[] pkAddr){
        this.pkAddr = pkAddr;
    }

    public int[] getPkAddr(){
        return pkAddr;
    }
}
