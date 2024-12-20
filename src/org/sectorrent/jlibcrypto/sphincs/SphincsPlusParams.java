package org.sectorrent.jlibcrypto.sphincs;

public class SphincsPlusParams {

    public static final int SPX_N = 16; // Hash output length in bytes

    public static final int CRYPTO_SEED_BYTES = 3*SPX_N;

    public static final int SPX_FULL_HEIGHT = 66; /* Height of the hypertree. */
    public static final int SPX_D = 22; // Number of subtree layers

    public static final int SPX_FORS_HEIGHT = 6;
    public static final int SPX_FORS_TREES = 33;
    public static final int SPX_WOTS_W = 16;

    public static final int SPX_ADDR_BYTES = 32;
    public static final int SPX_WOTS_LOGW = SPX_WOTS_W == 256 ? 8 : 4;

    public static final int SPX_WOTS_LEN1 = (8*SPX_N/SPX_WOTS_LOGW); // 32

    public static final int SPX_PK_BYTES = (2*SPX_N);
    public static final int SPX_SK_BYTES = (2*SPX_N+SPX_PK_BYTES);

    public static final int SPX_SHA256_BLOCK_BYTES = 64;

    public static final int SPX_WOTS_LEN2 = len(); // 3

    public static final int SPX_WOTS_LEN = (SPX_WOTS_LEN1+SPX_WOTS_LEN2); //  35
    public static final int SPX_WOTS_BYTES = (SPX_WOTS_LEN*SPX_N); // 560
    public static final int SPX_WOTS_PK_BYTES = SPX_WOTS_BYTES;

    public static final int SPX_TREE_HEIGHT = (SPX_FULL_HEIGHT/SPX_D);

    public static final int SPX_FORS_MSG_BYTES = ((SPX_FORS_HEIGHT*SPX_FORS_TREES+7)/8); // 25
    public static final int SPX_FORS_BYTES = ((SPX_FORS_HEIGHT+1)*SPX_FORS_TREES*SPX_N);
    public static final int SPX_FORS_PK_BYTES = SPX_N;

    public static final int SPX_BYTES = (SPX_N+SPX_FORS_BYTES+SPX_D*SPX_WOTS_BYTES+SPX_FULL_HEIGHT*SPX_N);

    public static final int SPX_OFFSET_LAYER = 0;   /* The byte used to specify the Merkle tree layer */
    public static final int SPX_OFFSET_TREE = 1;   /* The start of the 8 byte field used to specify the tree */
    public static final int SPX_OFFSET_TYPE = 9;   /* The byte used to specify the hash type (reason) */
    public static final int SPX_OFFSET_KP_ADDR2= 12;  /* The high byte used to specify the key pair (which one-time signature) */
    public static final int SPX_OFFSET_KP_ADDR1 = 13;  /* The low byte used to specify the key pair */
    public static final int SPX_OFFSET_CHAIN_ADDR =17;  /* The byte used to specify the chain address (which Winternitz chain) */
    public static final int SPX_OFFSET_HASH_ADDR = 21;  /* The byte used to specify the hash address (where in the Winternitz chain) */
    public static final int SPX_OFFSET_TREE_HGT = 17;  /* The byte used to specify the height of this node in the FORS or Merkle tree */
    public static final int SPX_OFFSET_TREE_INDEX =  18; /* The start of the 4 byte field used to specify the node in the FORS or Merkle tree */

    public static final int SPX_SHA2 = 1;

    public static final int SPX_SHA256_OUTPUT_BYTES = 32;  /* This does not necessarily equal SPX_N */

    public static final int SPX_SHA512_BLOCK_BYTES = 128;
    public static final int SPX_SHA512_OUTPUT_BYTES = 64;

    public static final int SPX_SHAX_BLOCK_BYTES = SPX_SHA256_BLOCK_BYTES;
    public static final int SPX_SHAX_OUTPUT_BYTES = SPX_SHA256_OUTPUT_BYTES;

    public static final int SPX_SHA256_ADDR_BYTES = 22;

    public static final int SPX_ADDR_TYPE_WOTS = 0;
    public static final int SPX_ADDR_TYPE_WOTSPK = 1;
    public static final int SPX_ADDR_TYPE_HASHTREE = 2;
    public static final int SPX_ADDR_TYPE_FORSTREE = 3;
    public static final int SPX_ADDR_TYPE_FORSPK = 4;
    public static final int SPX_ADDR_TYPE_WOTSPRF = 5;
    public static final int SPX_ADDR_TYPE_FORSPRF = 6;

    static {
        if(SPX_TREE_HEIGHT*SPX_D != SPX_FULL_HEIGHT){
            throw new IllegalStateException("SPX_D should always divide SPX_FULL_HEIGHT");
        }

        if(SPX_SHA256_OUTPUT_BYTES < SPX_N){
            throw new IllegalStateException("Linking against SHA-256 with N larger than 32 bytes is not supported");
        }
    }

    public static final int len(){
        if(SPX_WOTS_W == 256){
            if(SPX_N <= 1){
                return 1;

            }else if(SPX_N <= 256){
                return 2;
            }

            throw new IllegalStateException("Did not precompute SPX_WOTS_LEN2 for n outside {2, .., 256}");

        }else if(SPX_WOTS_W == 16){
            if(SPX_N <= 8){
                return 2;

            }else if(SPX_N <= 136){
                return 3;

            }else if(SPX_N <= 256){
                return 4;
            }

            throw new IllegalStateException("Did not precompute SPX_WOTS_LEN2 for n outside {2, .., 256}");
        }

        throw new IllegalStateException("Unknown SPX_WOTS_W");
    }
}
