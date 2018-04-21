import java.io.*;

/**
 * Class XTS yang berisikan perintah untuk melakuan enkripsi dekripsi
 * dengan menggunakan metode XTS mode dan AES
 * 
 * @author Grace Angelica
 * @author Stephen Jaya Gunawan
 * @author Ricky Putra Nursalim
 */
class XTS {
    private static int BLOCK_SIZE = 16; //128-bits (16-bytes)
    private static int KEY_LENGTH_HEX = 64; //256-bits (32-bytes)
    private static byte[] tweak = Util.hex2byte("98765432109876543210987654321098");

    private static int NUMBER_OF_THREAD = 100;
    
    private byte[] encryptTweak = null;
    private byte[][] tTable = null;

    /**
     * Initialize files (plaintext, ciphertext, key) needed for XTS-AES
     * 
     * @param forEncryption, true if data is used for encryption, else false
     * @param keyPath, file path containing the key
     * @param sourcePath, file path containing plain text
     * @param targetPath, file path containing cipher text
     */
    public void initProcessData(boolean forEncryption, String keyPath, String sourcePath, String targetPath) throws Exception {
        BufferedReader keyReader = new BufferedReader(new FileReader(keyPath));
        String key = keyReader.readLine();
        keyReader.close();

        String key1 = key.substring(0, KEY_LENGTH_HEX / 2);
        String key2 = key.substring(KEY_LENGTH_HEX / 2, key.length());

        System.out.println("key1\t= " + key1);
        System.out.println("key2\t= " + key2);
        System.out.println("tweak\t= " + Util.toHEX1(tweak));

        RandomAccessFile inFile = new RandomAccessFile((sourcePath), "r");
        RandomAccessFile outFile = new RandomAccessFile((targetPath), "rw");

        /** Convert HEX keys to bytes for encrypt/decrypt */
        byte[] k1 = Util.hex2byte(key1);
        byte[] k2 = Util.hex2byte(key2);

        processData(forEncryption, inFile, outFile, k1, k2, tweak);
        
        inFile.close();
        outFile.close();
    }

    /**
     * Encryption/Decryption process
     * Each block is encrypted/decryption using a single thread
     * 
     * @param forEncryption, true if data is used for encryption, else false
     * @param inText, file reference of the plain text
     * @param outText, file reference of the cipher text
     * @param k1, key 1, derived from K = K1 || K2 (concatenation)
     * @param k2, key 2, derived from K = K1 || K2 (concatenation)
     * @param tweak, tweak value
     */
    public void processData(boolean forEncryption, RandomAccessFile inText, RandomAccessFile outText, byte[] k1, byte[] k2, byte[] tweak) throws Exception {
        long fileSize = inText.length();

        int noIndependentProcess = (int) fileSize / BLOCK_SIZE;
        int noRemaindingBlock = (int) (fileSize % BLOCK_SIZE);

        /** Read plainText content for encryption or cipherText content for decryption */
        byte[][] inBuffer = new byte[noIndependentProcess + 1][16];
        inBuffer[noIndependentProcess] = new byte[noRemaindingBlock];
        for (int i = 0; i < inBuffer.length; i++) {
            inText.read(inBuffer[i]);
        }

        byte[][] outBuffer = new byte[noIndependentProcess + 1][16];
        outBuffer[noIndependentProcess] = new byte[noRemaindingBlock];

        AES aes = new AES();
        aes.setKey(k2);

        /** Create T table which stores T at sequence j */
        if (this.encryptTweak == null) this.encryptTweak = aes.encrypt(tweak);
        buildTLookup(this.encryptTweak, noIndependentProcess + 1); 

        /** Uses threading to process each block independently */
        Thread[] worker = new Thread[NUMBER_OF_THREAD];
        for (int j = 0; j <= noIndependentProcess - 2; j++) {
            worker[j % NUMBER_OF_THREAD] = new Thread(
                    new ProcessBlock(forEncryption, outBuffer[j], inBuffer[j], k1, j));
            worker[j % NUMBER_OF_THREAD].start();
            if (j % NUMBER_OF_THREAD == NUMBER_OF_THREAD - 1) {
                for (int i = 0; j < NUMBER_OF_THREAD; i++) {
                    if (worker[i] != null) {
                        worker[i].join(0);
                    }
                }
            }
        }
    
        for (int i = 0; i < NUMBER_OF_THREAD; i++) {
            if (worker[i] != null) {
                worker[i].join(0);
            }
        }

        /** Check if last block is less than 128 bits */
        if (noRemaindingBlock == 0) {
            /** The last block is not less, do the same process as the above */
            if (forEncryption) {
                encryptBlock(outBuffer[noIndependentProcess - 1], inBuffer[noIndependentProcess - 1], k1, noIndependentProcess - 1);
            } else {
                decryptBlock(outBuffer[noIndependentProcess - 1], inBuffer[noIndependentProcess - 1], k1, noIndependentProcess - 1);
            }
            outBuffer[noIndependentProcess] = new byte[0];
        } else {
            /** The last block is encrypted/decrypted using Ciphertext Stealing */
            byte[] cc = new byte[BLOCK_SIZE];
            if (forEncryption) {
                encryptBlock(cc, inBuffer[noIndependentProcess - 1], k1, noIndependentProcess - 1);
            } else {
                decryptBlock(cc, inBuffer[noIndependentProcess - 1], k1, noIndependentProcess - 1);
            }
            System.arraycopy(cc, 0, outBuffer[noIndependentProcess], 0, noRemaindingBlock);
            byte[] cp = new byte[16 - noRemaindingBlock];
            int ctr = 16 - noRemaindingBlock;
            int xx = cc.length - 1;
            int yy = cp.length - 1;
            while (ctr-- != 0) {
                cp[yy--] = cc[xx--];
            }
            byte[] pp = new byte[16];
            for (int a = 0; a < noRemaindingBlock; a++) {
                pp[a] = inBuffer[noIndependentProcess][a];
            }
            for (int a = noRemaindingBlock; a < pp.length; a++) {
                pp[a] = cp[a - noRemaindingBlock];
            }
            if (forEncryption) {
                encryptBlock(outBuffer[noIndependentProcess - 1], pp, k1, noIndependentProcess);
            } else {
                decryptBlock(outBuffer[noIndependentProcess - 1], pp, k1, noIndependentProcess);
            }
        }

        /** Write results to output file */
        for (int i = 0 ; i < outBuffer.length; i++) {    
            outText.write(outBuffer[i]);
        }
    }

    /**
     * Computes the encryption, C = E(P XOR T) XOR T
     * 
     * @param resultCipher, the encrypted block
     * @param plainText, the plain text block
     * @param key1, the key
     * @param j, number sequence
     * @param tweak, tweak number (i)
     */
    public void encryptBlock(byte[] resultCipher, byte[] plainText, byte[] key1, int j) {
        /** Gets the value of T in the table */
        byte[] t = tTable[j];
        AES aes = new AES();
        aes.setKey(key1);

        byte[] plainTextXorT = new byte[BLOCK_SIZE];
        /** Encrypt(P XOR T) with Key 1 */
        for (int x = 0; x < plainText.length; x++) {
            plainTextXorT[x] = (byte) (plainTextXorT[x] ^ t[x]);
        }

        byte[] cipherBlockXorT = aes.encrypt(plainTextXorT);

        /** Writes the output to resultCipher */
        for (int x = 0; x < cipherBlockXorT.length; x++) {
            resultCipher[x] = (byte) (cipherBlockXorT[x] ^ t[x]);
        } 
    }

    /**
    * Computes the decryption, P = D(C XOR T) XOR T
    * 
    * @param resultCipher, the decrypted block
    * @param plainText, the cipher text block
    * @param key1, the key
    * @param j, number sequence
    * @param tweak, tweak number (i)
    */
    public void decryptBlock(byte[] resultPlain, byte[] cipherText, byte[] key1, int j) {
        /** Gets the value of T in the table */
        byte[] t = tTable[j];
        AES aes = new AES();
        aes.setKey(key1);

        byte[] cipherTextXorT = new byte[BLOCK_SIZE];
        /** Decrypt(P XOR T) with Key 1 */
        for (int x = 0; x < cipherText.length; x++) {
            cipherTextXorT[x] = (byte) (cipherTextXorT[x] ^ t[x]);
        }

        byte[] plainBlockXorT = aes.encrypt(cipherTextXorT);

        /** Writes the output to resultCipher */
        for (int x = 0; x < plainBlockXorT.length; x++) {
            resultPlain[x] = (byte) (plainBlockXorT[x] ^ t[x]);
        }
    }

    /** 
     * Build a lookup table which computes T = E(i) XOR alpha^j using key2
     * For easier and faster computation
     * 
     * @param a, first value of Encrypt(tweak) 
     * @param numBlock, how many sequence j to compute
     */
    public void buildTLookup(byte[] a, int numBlock) {
        tTable = new byte[numBlock][BLOCK_SIZE];
        tTable[0] = a;
        for (int i = 1; i < numBlock; i++) {
            tTable[i][0] = (byte) ((2 * (tTable[i - 1][0] % 128)) ^ (135 * (tTable[i - 1][15] / 128)));
            for (int k = 1; k < 16; k++) {
                tTable[i][k] = (byte) ((2 * (tTable[i - 1][k] % 128)) ^ (tTable[i - 1][k - 1] / 128));
            }
        }
    }

    /**
     * Class Runnable yang digunakan untuk mulithreading
     * Multithreading untuk proses encrypt/decrypt per block
     * 
     */
    class ProcessBlock implements Runnable {

        private boolean forEncryption;
        private byte[] dest;
        private byte[] source;
        private byte[] key1;
        private int j;

        // Constructor
        public ProcessBlock(boolean forEncryption, byte[] dest, byte[] source, byte[] key1, int j) {
            this.forEncryption = forEncryption;
            this.dest = dest;
            this.source = source;
            this.key1 = key1;
            this.j = j;
        }

        @Override
        public void run() {
            if (forEncryption) {
                encryptBlock(dest, source, key1, j);
            } else {
                decryptBlock(dest, source, key1, j);
            }
        }
    }

}