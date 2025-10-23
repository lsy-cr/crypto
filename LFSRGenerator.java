import java.util.ArrayList;
import java.util.List;

public class LFSRGenerator {
    // 生成LFSR密钥流
    public static List<Integer> generateKeyStream(List<Integer> initState) {
        List<Integer> keyStream = new ArrayList<>(initState);
        int n = initState.size(); // LFSR级数
        int maxLength = 31;

        // 按递推关系 key[5+k] = key[3+k] ⊕ key[k] 生成剩余密钥流
        for (int k = 0; k < maxLength - n; k++) {
            int nextBit = keyStream.get(3 + k) ^ keyStream.get(k); // 异或运算
            keyStream.add(nextBit);
        }
        return keyStream;
    }

    // LFSR加密方法
    public static String encryptWithLFSR(String plaintext, List<Integer> keyStream) {
        List<Integer> keyGroups = new ArrayList<>();
        List<Integer> extendedKeyStream = new ArrayList<>(keyStream);

        // 当明文过长时，扩展密钥流
        while (extendedKeyStream.size() / 7 < plaintext.length()) {
            extendedKeyStream.addAll(extendedKeyStream);
        }

        // 将密钥流按7位分组，转换为十进制数值（用于异或）
        for (int i = 0; i < extendedKeyStream.size(); i += 7) {
            int end = Math.min(i + 7, extendedKeyStream.size());
            List<Integer> group = extendedKeyStream.subList(i, end);
            int groupValue = 0;
            for (int bit : group) {
                groupValue = (groupValue << 1) | bit; // 位运算转换为数值
            }
            keyGroups.add(groupValue);
        }

        // 明文与密钥组异或，生成密文
        StringBuilder ciphertext = new StringBuilder();
        for (int i = 0; i < plaintext.length(); i++) {
            char plainChar = plaintext.charAt(i);
            int keyNum = keyGroups.get(i);
            char encryptedChar = (char) (plainChar ^ keyNum); // 异或加密
            ciphertext.append(encryptedChar);
        }
        return ciphertext.toString();
    }

    // 测试方法
    public static void main(String[] args) {

        List<Integer> initState = List.of(1, 1, 0, 0, 1);
        // 生成LFSR密钥流
        List<Integer> keyStream = generateKeyStream(initState);

        // 测试1：明文"abc"
        String plaintext1 = "abc";
        String ciphertext1 = encryptWithLFSR(plaintext1, keyStream);
        System.out.println("明文 '" + plaintext1 + "' 的密文：" + ciphertext1);

        // 测试2：明文"abcabcabcabc"
        String plaintext2 = "abcabcabcabc";
        String ciphertext2 = encryptWithLFSR(plaintext2, keyStream);
        System.out.println("明文 '" + plaintext2 + "' 的密文：" + ciphertext2);
    }
}
