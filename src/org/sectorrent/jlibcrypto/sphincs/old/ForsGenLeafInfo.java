package org.sectorrent.jlibcrypto.sphincs.old;

public class ForsGenLeafInfo {

    private int[] leafAddrX = new int[8];

    public ForsGenLeafInfo(){
    }

    public void setLeafAddrX(int[] leafAddrX){
        this.leafAddrX = leafAddrX;
    }

    public int[] getLeafAddrX(){
        return leafAddrX;
    }
}