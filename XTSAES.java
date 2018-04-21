import java.util.Arrays;

public final class XTSAES {
    private static final int XTS_DATA_UNIT_SIZE = 512;
    private static final int SIZE_OF_LONG = 8;
    private static int BLOCK_SIZE;

    private BlockCipher cipherInstance;
    private final BlockCipher tweakCipherInstance;

    public XTSAES(final BlockCipher cipher, final BlockCipher tweakCipher) throws IllegalStateException {
        if (!cipher.getAlgorithmName().equals(tweakCipher.getAlgorithmName()))
            throw new IllegalStateException();

        this.cipherInstance = cipher;
        this.tweakCipherInstance = tweakCipher;
        BLOCK_SIZE = cipher.getBlockSize();
    }

    public int processDataUnit(byte[] in, final int inOffset, byte[] out, final int outOffset, final long dataUnitNumber) throws IllegalStateException {
        int processedBytes = in.length - inOffset;
        // Check if the length of in is a multiple of BLOCK_SIZE
        if (processedBytes % BLOCK_SIZE != 0)
            throw new IllegalStateException();

        // Produce the tweak value
        byte[] tweak = new byte[BLOCK_SIZE];
        // Convert the dataUnitNumber (long) to little-endian bytes
        ByteUtil.storeInt64LE(dataUnitNumber, tweak, 0);
        // A long consists of 8 bytes but the block size is 16 so we
        // fill the rest of the IV array with zeros.
        Arrays.fill(tweak, SIZE_OF_LONG, BLOCK_SIZE, (byte) 0);
        // Encrypt tweak
        this.tweakCipherInstance.processBlock(tweak, 0, tweak, 0);

        for (int i = 0; i < XTS_DATA_UNIT_SIZE; i += BLOCK_SIZE) {
            // Encrypt / decrypt one block
            this.processBlock(in, inOffset + i, out, outOffset + i, tweak);
            // Multiply tweak by alpha
            tweak = this.multiplyTweakByA(tweak);
        }

        return processedBytes;
    }

    public String getAlgorithmName() {
        return this.cipherInstance.getAlgorithmName();
    }

    public final int getDataUnitSize() {
        return XTS_DATA_UNIT_SIZE;
    }

    public final int getBlockSize() {
        return BLOCK_SIZE;
    }

    public void resetCipher(final BlockCipher cipher) {
        this.cipherInstance = cipher;
    }

    private int processBlock(byte[] in, final int inOffset, byte[] out, final int outOffset, final byte[] tweak) {
        // XOR
        // PP <- P ^ T
        for (int i = 0; i < BLOCK_SIZE; i++)
            in[inOffset + i] ^= tweak[i];

        // Encrypt	  CC <- enc(Key1, PP)
        // Or decrypt PP <- dec(Key1, CC)
        this.cipherInstance.processBlock(in, inOffset, out, outOffset);

        // XOR
        // C <- CC ^ T
        for (int i = 0; i < BLOCK_SIZE; i++)
            out[outOffset + i] ^= tweak[i];

        return BLOCK_SIZE;
    }

    private byte[] multiplyTweakByA(final byte[] tweak) {
        long whiteningLo = ByteUtil.loadInt64LE(tweak, 0);
        long whiteningHi = ByteUtil.loadInt64LE(tweak, SIZE_OF_LONG);

        int finalCarry = 0 == (whiteningHi & 0x8000000000000000L) ? 0 : 135;

        whiteningHi <<= 1;
        whiteningHi |= whiteningLo >>> 63;
        whiteningLo <<= 1;
        whiteningLo ^= finalCarry;

        ByteUtil.storeInt64LE(whiteningLo, tweak, 0);
        ByteUtil.storeInt64LE(whiteningHi, tweak, SIZE_OF_LONG);

        return tweak;
    }
}