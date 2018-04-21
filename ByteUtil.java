public final class ByteUtil {

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

    public static final String humanReadableByteCount(final long bytes) {
        final int unit = 1024;
        if (bytes < unit)
            return bytes + " B";

        int exp = (int) (Math.log(bytes) / Math.log(unit));
        String pre = ("KMGTPE").charAt(exp - 1) + ("");
        return String.format("%.1f %sB", bytes / Math.pow(unit, exp), pre);
    }

    public static final boolean arraysAreEqual(final byte[] array1, final byte[] array2) {
        if (array1.length != array2.length)
            return false;

        for (int i = 0; i < array1.length; i++) {
            if (array1[i] != array2[i])
                return false;
        }

        return true;
    }

    public final static short loadInt16BE(byte[] bytes, int offset) {
        return (short) (((bytes[offset] & 0xff) << 8) |
                (bytes[offset + 1] & 0xff));
    }

    public final static int loadInt32LE(final byte[] bytes, int offSet) {
        return (bytes[offSet + 3] << 24) |
                ((bytes[offSet + 2] & 0xff) << 16) |
                ((bytes[offSet + 1] & 0xff) << 8) |
                (bytes[offSet] & 0xff);
    }

    public final static int loadInt32BE(byte[] bytes, int offSet) {
        return (bytes[offSet] << 24) |
                ((bytes[offSet + 1] & 0xff) << 16) |
                ((bytes[offSet + 2] & 0xff) << 8) |
                (bytes[offSet + 3] & 0xff);
    }

    public final static long loadInt64LE(final byte[] bytes, int offSet) {
        return (loadInt32LE(bytes, offSet) & 0x0ffffffffL) |
                ((long) loadInt32LE(bytes, offSet + 4) << 32);
    }


    public final static long loadInt64BE(byte[] bytes, int offSet) {
        return (loadInt32BE(bytes, offSet + 4) & 0x0ffffffffL) |
                ((long) loadInt32BE(bytes, offSet) << 32);
    }


    public final static void storeInt32LE(int value, byte[] bytes, int offSet) {
        bytes[offSet] = (byte) (value);
        bytes[offSet + 1] = (byte) (value >>> 8);
        bytes[offSet + 2] = (byte) (value >>> 16);
        bytes[offSet + 3] = (byte) (value >>> 24);
    }

    public final static void storeInt32BE(int value, byte[] bytes, int offSet) {
        bytes[offSet + 3] = (byte) (value);
        bytes[offSet + 2] = (byte) (value >>> 8);
        bytes[offSet + 1] = (byte) (value >>> 16);
        bytes[offSet] = (byte) (value >>> 24);
    }

    public final static void storeInt64LE(long value, byte[] bytes, int offSet) {
        storeInt32LE((int) (value >>> 32), bytes, offSet + 4);
        storeInt32LE((int) (value), bytes, offSet);
    }
}