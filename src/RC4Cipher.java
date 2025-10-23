import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class RC4Cipher {
    public static List<String> encryptWithRC4(String plaintext, String key) {
        // 1. 密钥调度算法（KSA）：初始化并打乱S表
        int[] S = new int[256];
        int[] T = new int[256];
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        int keyLength = keyBytes.length;

        // 初始化S表
        for (int i = 0; i < 256; i++) {
            S[i] = i;
            T[i] = keyBytes[i % keyLength] & 0xFF; // 转换为无符号字节
        }

        // 置换S表
        int j = 0;
        for (int i = 0; i < 256; i++) {
            j = (j + S[i] + T[i]) % 256;
            // 交换S[i]和S[j]
            int temp = S[i];
            S[i] = S[j];
            S[j] = temp;
        }

        // 2. 伪随机数生成算法（PRGA）：生成密钥流并加密
        List<String> cipherHexList = new ArrayList<>();
        int i = 0;
        j = 0;
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);

        for (byte plainByte : plaintextBytes) {
            i = (i + 1) % 256;
            j = (j + S[i]) % 256;
            // 交换S[i]和S[j]
            int temp = S[i];
            S[i] = S[j];
            S[j] = temp;

            // 生成1字节密钥流并异或加密
            int t = (S[i] + S[j]) % 256;
            int keyByte = S[t];
            int cipherByte = (plainByte & 0xFF) ^ keyByte; // 异或运算（无符号处理）

            // 转换为两位16进制字符串
            cipherHexList.add(String.format("%02x", cipherByte));
        }
        return cipherHexList;
    }

    // 辅助方法：16进制密文列表转换为字符串
    public static String hexListToString(List<String> hexList) {
        StringBuilder hexStr = new StringBuilder();
        for (String hex : hexList) {
            hexStr.append(hex).append(" ");
        }
        return hexStr.toString().trim();
    }

    public static void main(String[] args) {
        String rc4Key = "cipherByRC4"; 

        // 测试1：明文"abab"
        String plaintext1 = "abab";
        List<String> cipherHex1 = encryptWithRC4(plaintext1, rc4Key);
        System.out.println("明文 '" + plaintext1 + "' 的密文（16进制）：" + hexListToString(cipherHex1));

        // 测试2：明文"9876"
        String plaintext2 = "9876";
        List<String> cipherHex2 = encryptWithRC4(plaintext2, rc4Key);
        System.out.println("明文 '" + plaintext2 + "' 的密文（16进制）：" + hexListToString(cipherHex2));

        // 测试3：明文"12345678"
        String plaintext3 = "12345678";
        List<String> cipherHex3 = encryptWithRC4(plaintext3, rc4Key);
        System.out.println("明文 '" + plaintext3 + "' 的密文（16进制）：" + hexListToString(cipherHex3));
    }
}
