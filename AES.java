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

    private String keyHex;


    public AES(byte[] keyHex) {
        this.keyHex = ByteUtil.bytesToHex(keyHex);
    }

    public byte[] encrypt(byte[] textHex) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        SecretKey key = new SecretKeySpec(DatatypeConverter.parseHexBinary(keyHex), "AES");

        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] result = cipher.doFinal(DatatypeConverter.parseHexBinary(ByteUtil.bytesToHex(textHex)));

        return result;
    }
    
    public byte[] decrypt(byte[] textHex) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        SecretKey key = new SecretKeySpec(DatatypeConverter.parseHexBinary(keyHex), "AES");

        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key);

        byte[] result = cipher.doFinal(DatatypeConverter.parseHexBinary(ByteUtil.bytesToHex(textHex)));

        return result;
    }

}