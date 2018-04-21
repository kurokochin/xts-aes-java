
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


public class XTS {
    
    /** Encryption mode properties */
    private String file;
    private String out;
    private int block_size;
    private int key_length_hex;
    
    /** Lookup table for multiplying alpha */
    private byte[][] tTable;
    /** Tweak values */
    private byte[] encryptTweak = ByteUtil.hexToBytes("12345678901234567890123456789012");
    
    /** How many full blocks m, and the remaining block b that are less than 128bits*/
    private int m;
    private int b;
    
    /** Key1 and Key2, derived from K = K1 || K2 (Concatenation) */
    private byte[] key1;
    private byte[] key2;

    /**
     * Constructor for initialize files (plaintext, ciphertext, key) needed for XTS-AES
     * 
     * @param file, file path containing input file
     * @param key, file path containing the key
     * @param out, file path containing output file
     */
    public XTS(String file, String key, String out) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        this.file = file;
        this.block_size = 16;
        this.key_length_hex = 64;
        this.out = out;

        BufferedReader brKey = new BufferedReader(new FileReader(key));
        String read = brKey.readLine();
        this.key1 = ByteUtil.hexToBytes(read.substring(0, key_length_hex / 2));
        this.key2 = ByteUtil.hexToBytes(read.substring(key_length_hex / 2, read.length()));
        brKey.close();

        RandomAccessFile brFile = new RandomAccessFile(file, "r");
        long fileSize = brFile.length();
        brFile.close();
        this.m = (int) (fileSize / block_size);
        this.b = (int) (fileSize % block_size);

        AES aes = new AES(this.key2);
        buildTLookup(aes.encrypt(encryptTweak));
    }


    public void encrypt() throws Exception {
        RandomAccessFile brFile = new RandomAccessFile(file, "r");
        byte[][] input = new byte[m + 1][block_size];
        input[m] = new byte[b];
        byte[][] output = new byte[m + 1][block_size];
        output[m] = new byte[b];
        for (int i = 0; i < input.length; i++) {
            brFile.read(input[i]);
        }

        for (int q = 0; q <= m - 2; q++) {
            output[q] = blockEnc(key1, key2, input[q], q);
        }

        /** Check if it is needed to do ciphertext stealing */
        if (b == 0) {
            output[m - 1] = blockEnc(key1, key2, input[m - 1], m - 1);
            output[m] = new byte[0];
        } else {
            byte[] cc = blockEnc(key1, key2, input[m - 1], m - 1);
            System.arraycopy(cc, 0, output[m], 0, b);
            byte[] cp = new byte[block_size - b];
            for (int i = b; i < block_size; i++)
                cp[i - b] = cc[i];

            byte[] pp = new byte[input[m].length + cp.length];
            System.arraycopy(input[m], 0, pp, 0, input[m].length);
            System.arraycopy(cp, 0, pp, input[m].length, cp.length);

            output[m - 1] = blockEnc(key1, key2, pp, m);

        }

        brFile.close();

        RandomAccessFile brOut = new RandomAccessFile(out, "rw");
        for (int i = 0; i < output.length; i++) {
            for (int j = 0; j < output[i].length; j++)
                brOut.write(output[i][j]);
        }
        brOut.close();
    }

    /** Encryption per block */
    public byte[] blockEnc(byte[] key1, byte[] key2, byte[] p, int j) throws Exception {
        AES aes = new AES(key2);
        byte[] t = tTable[j];
        byte[] pp = xortweaktext(t, p);
        aes = new AES(key1);
        byte[] cc = aes.encrypt(pp);
        byte[] c = xortweaktext(t, cc);

        return c;
    }

    public void decrypt() throws Exception {
        RandomAccessFile brFile = new RandomAccessFile(file, "r");
        byte[][] input = new byte[m + 1][block_size];
        input[m] = new byte[b];
        byte[][] output = new byte[m + 1][block_size];
        output[m] = new byte[b];
        for (int i = 0; i < input.length; i++) {
            brFile.read(input[i]);
        }

        for (int q = 0; q <= m - 2; q++) {
            output[q] = blockDec(key1, key2, input[q], q);
        }
        /** Check if it is needed to do ciphertext stealing */
        if (b == 0) {
            output[m - 1] = blockDec(key1, key2, input[m - 1], m - 1);
            output[m] = new byte[0];
        } else {
            byte[] pp = blockDec(key1, key2, input[m - 1], m);
            System.arraycopy(pp, 0, output[m], 0, b);
            byte[] cp = new byte[block_size - b];
            for (int i = b; i < block_size; i++)
                cp[i - b] = pp[i];

            byte[] cc = new byte[input[m].length + cp.length];
            System.arraycopy(input[m], 0, cc, 0, input[m].length);
            System.arraycopy(cp, 0, cc, input[m].length, cp.length);

            output[m - 1] = blockDec(key1, key2, cc, m - 1);

        }

        brFile.close();

        RandomAccessFile brOut = new RandomAccessFile(out, "rw");
        for (int i = 0; i < output.length; i++) {
            for (int j = 0; j < output[i].length; j++)
                brOut.write(output[i][j]);
        }
        brOut.close();
    }

    /** Decryption per block */
    public byte[] blockDec(byte[] key1, byte[] key2, byte[] c, int j) throws Exception {
        AES aes = new AES(key2);
        byte[] t = tTable[j];
        byte[] cc = xortweaktext(t, c);
        aes = new AES(key1);
        byte[] pp = aes.decrypt(cc);
        byte[] p = xortweaktext(t, pp);

        return p;

    }

    /** Create lookup table for T = encrypt(i) * alpha^j */
    public void buildTLookup(byte[] tweakEncrypt) {
        byte[][] tTable = new byte[m + 1][block_size];
        tTable[0] = tweakEncrypt;
        for (int i = 1; i < m + 1; i++) {
            tTable[i][0] = (byte) ((2 * (tTable[i - 1][0] % 128)) ^ (135 * (tTable[i - 1][15] / 128)));
            for (int k = 1; k < 16; k++) {
                tTable[i][k] = (byte) ((2 * (tTable[i - 1][k] % 128)) ^ (tTable[i - 1][k - 1] / 128));
            }
        }
        this.tTable = tTable;
    }

    /** XOR operation between byte in block and T */
    public byte[] xortweaktext(byte[] tweakEncrypt, byte[] textBlock) {
        byte[] result = new byte[16];
        for (int i = 0; i < tweakEncrypt.length; i++) {
            result[i] = (byte) (tweakEncrypt[i] ^ textBlock[i]);
        }
        return result;
    }

}