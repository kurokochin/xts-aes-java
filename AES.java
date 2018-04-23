import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class AES {

    /** Key to be used for encrypt/decrypt */
    private String keyHex;

    public AES(byte[] keyHex) {
        this.keyHex = ByteUtil.bytesToHex(keyHex);
    }

    /**
     * Encryption method using AES, using javax.crypto library
     * @param textHex, byte to be encrypted
     */
    public byte[] encrypt(byte[] textHex) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        SecretKey key = new SecretKeySpec(DatatypeConverter.parseHexBinary(keyHex), "AES");

        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] result = cipher.doFinal(DatatypeConverter.parseHexBinary(ByteUtil.bytesToHex(textHex)));

        return result;
    }
    

    /**
     * Decryption method using AES, using javax.crypto library
     * @param textHex, byte to be decrypted
     */
    public byte[] decrypt(byte[] textHex) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        SecretKey key = new SecretKeySpec(DatatypeConverter.parseHexBinary(keyHex), "AES");

        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key);

        byte[] result = cipher.doFinal(DatatypeConverter.parseHexBinary(ByteUtil.bytesToHex(textHex)));

        return result;
    }

}