package org.sectorrent.jlibcrypto.sphincs;

public abstract class BaseHash {

    protected String name;
    protected int hashSize, blockSize;
    protected long count;
    protected byte[] buffer;

    protected BaseHash(String name, int hashSize, int blockSize){
        super();

        this.name = name;
        this.hashSize = hashSize;
        this.blockSize = blockSize;
        this.buffer = new byte[blockSize];

        resetContext();
    }

    public String name(){
        return name;
    }

    public int hashSize(){
        return hashSize;
    }

    public int blockSize(){
        return blockSize;
    }

    public void update(byte b){
        int i = (int) (count%blockSize);
        count++;
        buffer[i] = b;

        if(i == (blockSize-1)){
            transform(buffer, 0);
        }
    }

    public void update(byte[] b){
        update(b, 0, b.length);
    }

    public void update(byte[] b, int offset, int len){
        int n = (int) (count%blockSize);
        count += len;
        int partLen = blockSize-n;
        int i = 0;

        if(len >= partLen){
            System.arraycopy(b, offset, buffer, n, partLen);
            transform(buffer, 0);
            for(i = partLen; i+blockSize-1 < len; i += blockSize){
                transform(b, offset+i);
            }

            n = 0;
        }

        if(i < len){
            System.arraycopy(b, offset+i, buffer, n, len-i);
        }
    }

    public byte[] digest(){
        byte[] tail = padBuffer(); // pad remaining bytes in buffer
        update(tail, 0, tail.length); // last transform of a message
        byte[] result = getResult(); // make a result out of context

        reset(); // reset this instance for future re-use

        return result;
    }

    public void reset(){
        count = 0L;
        for(int i = 0; i < blockSize; i++){
            buffer[i] = 0;
        }

        resetContext();
    }

    public abstract Object clone();

    protected abstract byte[] padBuffer();

    protected abstract byte[] getResult();

    protected abstract void resetContext();

    protected abstract void transform(byte[] in, int offset);
}
