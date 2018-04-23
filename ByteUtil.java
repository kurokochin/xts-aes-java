public final class ByteUtil {

    /** Helper class for converting bytes to hex representation
     * @param bytes, the array of bytes
     */
    public static final String bytesToHex(final byte[] bytes) {
        if (bytes == null)
            return null;
        else {
            int length = bytes.length;
            String hexBytes = "";
            for (int i = 0; i < length; i++) {
                if ((bytes[i] & 0xFF) < 16) {
                    hexBytes += "0";
                    hexBytes += Integer.toHexString(bytes[i] & 0xFF);
                } else
                    hexBytes += Integer.toHexString(bytes[i] & 0xFF);
            }

            return hexBytes;
        }
    }

    /**
     * Convert hex strings to array of bytes
     * @param hexBytes, the hex strings
     */
    public static final byte[] hexToBytes(final String hexBytes) {
        if (hexBytes == null | hexBytes.length() < 2)
            return null;
        else {
            int length = hexBytes.length() / 2;
            byte[] buffer = new byte[length];
            for (int i = 0; i < length; i++)
                buffer[i] = (byte) Integer.parseInt(hexBytes.substring(i * 2, i * 2 + 2), 16);

            return buffer;
        }
    }
}