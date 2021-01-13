
public class AESUtil {

    /**
     * 二进制byte[]转十六进制string
     */
    public static String byteToHexString(byte[] bytes) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < bytes.length; i++) {
            String strHex = Integer.toHexString(bytes[i] & 0xff);
            if (strHex.length() < 2) {
                sb.append("0" + strHex);
            } else {
                sb.append(strHex);
            }
        }
        return sb.toString();
    }

    /**
     * 十六进制string转二进制byte[]
     */
    public static byte[] hexStringToByte(String s) {
        byte[] baKeyword = new byte[s.length() / 2];
        for (int i = 0; i < baKeyword.length; i++) {
            baKeyword[i] = (byte) (0xff & Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16));
        }
        return baKeyword;
    }

    public static String encry(String decryMsg, String key) throws Exception {
        byte[] keyBytes = hexStringToByte(key);
        SecretKeySpec sKeySpec = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, sKeySpec);
        byte[] encryBytes = cipher.doFinal(decryMsg.getBytes("utf8"));
        return byteToHexString(encryBytes);
    }

    public static String decry(String encryMsg, String key) throws Exception {
        byte[] keyBytes = hexStringToByte(key);
        byte[] encry_bytes = hexStringToByte(encryMsg);
        SecretKeySpec sKeySpec = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, sKeySpec);
        byte[] decry_bytes = cipher.doFinal(encry_bytes);
        return new String(decry_bytes, "utf8");
    }

    public static void main(String[] args) throws Exception {
        String key ="5d6cc2e7d8da6cb6b24fb673fa628c18";
        System.out.printf("key:%s%n", key);
        String origin = "111222333444555";
        String after = encry(origin, key);
        System.out.printf("encry:%s%n", after);
        after = decry(after, key);
        System.out.printf("decry:%s%n", after);
    }
}