package org.sectorrent.jlibcrypto.sphincs.utils;

public class ForsGenLeafInfo {

    private int[] leafAddrX = new int[8];

    public ForsGenLeafInfo(){
    }

    public void setLeafAddressX(int[] leafAddrX){
        this.leafAddrX = leafAddrX;
    }

    public int[] getLeafAddressX(){
        return leafAddrX;
    }
}
