import java.util.*;

public class Main {

    // ==================== 矩阵密码 ====================
    public static String matrixEncrypt(String plaintext, String key) {
        plaintext = plaintext.replaceAll(" ", "").toLowerCase();
        int cols = key.length();
        int rows = (int) Math.ceil((double) plaintext.length() / cols);
        char[][] matrix = new char[rows][cols];

        int index = 0;
        for (int i = 0; i < rows; i++) {
            for (int j = 0; j < cols; j++) {
                if (index < plaintext.length()) {
                    matrix[i][j] = plaintext.charAt(index++);
                } else {
                    matrix[i][j] = ' ';
                }
            }
        }

        int[] keyOrder = new int[cols];
        for (int i = 0; i < cols; i++) {
            keyOrder[i] = Integer.parseInt(String.valueOf(key.charAt(i)));
        }

        StringBuilder ciphertext = new StringBuilder();
        for (int col = 1; col <= cols; col++) {
            for (int i = 0; i < cols; i++) {
                if (keyOrder[i] == col) {
                    for (int j = 0; j < rows; j++) {
                        if (matrix[j][i] != ' ') {
                            ciphertext.append(matrix[j][i]);
                        }
                    }
                    break;
                }
            }
        }
        return ciphertext.toString();
    }

    public static String matrixDecrypt(String ciphertext, String key) {
        int cols = key.length();
        int rows = (int) Math.ceil((double) ciphertext.length() / cols);
        char[][] matrix = new char[rows][cols];

        int[] keyOrder = new int[cols];
        for (int i = 0; i < cols; i++) {
            keyOrder[i] = Integer.parseInt(String.valueOf(key.charAt(i)));
        }

        int[] colLengths = new int[cols];
        int total = ciphertext.length();
        for (int col = 1; col <= cols; col++) {
            for (int i = 0; i < cols; i++) {
                if (keyOrder[i] == col) {
                    colLengths[i] = Math.min(rows, total);
                    total -= colLengths[i];
                    break;
                }
            }
        }

        int index = 0;
        for (int col = 1; col <= cols; col++) {
            for (int i = 0; i < cols; i++) {
                if (keyOrder[i] == col) {
                    for (int j = 0; j < colLengths[i]; j++) {
                        if (index < ciphertext.length()) {
                            matrix[j][i] = ciphertext.charAt(index++);
                        }
                    }
                    break;
                }
            }
        }

        StringBuilder plaintext = new StringBuilder();
        for (int i = 0; i < rows; i++) {
            for (int j = 0; j < cols; j++) {
                if (matrix[i][j] != 0) {
                    plaintext.append(matrix[i][j]);
                }
            }
        }
        return plaintext.toString();
    }

    // ==================== 单表代替密码 ====================
    public static String substitutionEncrypt(String plaintext, String keyBox) {
        StringBuilder ciphertext = new StringBuilder();
        for (char c : plaintext.toCharArray()) {
            if (Character.isLetter(c)) {
                char base = Character.isLowerCase(c) ? 'a' : 'A';
                int idx = c - base;
                ciphertext.append(keyBox.charAt(idx));
            } else {
                ciphertext.append(c);
            }
        }
        return ciphertext.toString();
    }

    public static String substitutionDecrypt(String ciphertext, String keyBox) {
        StringBuilder plaintext = new StringBuilder();
        for (char c : ciphertext.toCharArray()) {
            if (Character.isLetter(c)) {
                char base = Character.isLowerCase(c) ? 'a' : 'A';
                int idx = keyBox.indexOf(c);
                plaintext.append((char) (base + idx));
            } else {
                plaintext.append(c);
            }
        }
        return plaintext.toString();
    }

    // ==================== 仿射密码 ====================
    private static int gcd(int a, int b) {
        return b == 0 ? a : gcd(b, a % b);
    }

    private static int modInverse(int a, int m) {
        for (int i = 1; i < m; i++) {
            if ((a * i) % m == 1) {
                return i;
            }
        }
        return -1;
    }

    public static String affineEncrypt(String plaintext, int a, int b) {
        if (gcd(a, 26) != 1) {
            throw new IllegalArgumentException("a 和 26 必须互质");
        }
        StringBuilder ciphertext = new StringBuilder();
        for (char c : plaintext.toCharArray()) {
            if (Character.isLetter(c)) {
                char base = Character.isLowerCase(c) ? 'a' : 'A';
                int x = c - base;
                int y = (a * x + b) % 26;
                ciphertext.append((char) (base + y));
            } else {
                ciphertext.append(c);
            }
        }
        return ciphertext.toString();
    }

    public static String affineDecrypt(String ciphertext, int a, int b) {
        int aInv = modInverse(a, 26);
        if (aInv == -1) {
            throw new IllegalArgumentException("a 在模 26 下无逆元");
        }
        StringBuilder plaintext = new StringBuilder();
        for (char c : ciphertext.toCharArray()) {
            if (Character.isLetter(c)) {
                char base = Character.isLowerCase(c) ? 'a' : 'A';
                int y = c - base;
                int x = (aInv * (y - b + 26)) % 26;
                plaintext.append((char) (base + x));
            } else {
                plaintext.append(c);
            }
        }
        return plaintext.toString();
    }

    // ==================== 维吉尼亚密码 ====================
    public static String vigenereEncrypt(String plaintext, String key) {
        StringBuilder ciphertext = new StringBuilder();
        key = key.toLowerCase();
        int keyLen = key.length();
        int keyIndex = 0;
        for (char c : plaintext.toCharArray()) {
            if (Character.isLetter(c)) {
                char base = Character.isLowerCase(c) ? 'a' : 'A';
                int p = c - base;
                int k = key.charAt(keyIndex % keyLen) - 'a';
                int enc = (p + k) % 26;
                ciphertext.append((char) (base + enc));
                keyIndex++;
            } else {
                ciphertext.append(c);
            }
        }
        return ciphertext.toString();
    }

    public static String vigenereDecrypt(String ciphertext, String key) {
        StringBuilder plaintext = new StringBuilder();
        key = key.toLowerCase();
        int keyLen = key.length();
        int keyIndex = 0;
        for (char c : ciphertext.toCharArray()) {
            if (Character.isLetter(c)) {
                char base = Character.isLowerCase(c) ? 'a' : 'A';
                int enc = c - base;
                int k = key.charAt(keyIndex % keyLen) - 'a';
                int dec = (enc - k + 26) % 26;
                plaintext.append((char) (base + dec));
                keyIndex++;
            } else {
                plaintext.append(c);
            }
        }
        return plaintext.toString();
    }

    // ==================== 主菜单 ====================
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        while (true) {
            System.out.println("\n=== 古典密码系统 ===");
            System.out.println("1. 矩阵密码");
            System.out.println("2. 单表代替密码");
            System.out.println("3. 仿射密码");
            System.out.println("4. 维吉尼亚密码");
            System.out.println("5. 退出");
            System.out.print("请选择加密方式: ");

            int choice = scanner.nextInt();
            scanner.nextLine();

            if (choice == 5) break;

            switch (choice) {
                case 1:
                    testMatrixCipher(scanner);
                    break;
                case 2:
                    testSubstitutionCipher(scanner);
                    break;
                case 3:
                    testAffineCipher(scanner);
                    break;
                case 4:
                    testVigenereCipher(scanner);
                    break;
                default:
                    System.out.println("无效选择");
            }
        }
        scanner.close();
    }

    private static void testMatrixCipher(Scanner scanner) {
        System.out.print("输入明文: ");
        String plaintext = scanner.nextLine();
        System.out.print("输入密钥（数字字符串）: ");
        String key = scanner.nextLine();

        String cipher = matrixEncrypt(plaintext, key);
        System.out.println("密文: " + cipher);
        System.out.println("解密: " + matrixDecrypt(cipher, key));
    }

    private static void testSubstitutionCipher(Scanner scanner) {
        System.out.print("输入明文: ");
        String plaintext = scanner.nextLine();
        String keyBox = "jpveywdulthaorgszmibxcqfnk"; // 示例代替表

        String cipher = substitutionEncrypt(plaintext, keyBox);
        System.out.println("密文: " + cipher);
        System.out.println("解密: " + substitutionDecrypt(cipher, keyBox));
    }

    private static void testAffineCipher(Scanner scanner) {
        System.out.print("输入明文: ");
        String plaintext = scanner.nextLine();
        System.out.print("输入 a: ");
        int a = scanner.nextInt();
        System.out.print("输入 b: ");
        int b = scanner.nextInt();
        scanner.nextLine();

        try {
            String cipher = affineEncrypt(plaintext, a, b);
            System.out.println("密文: " + cipher);
            System.out.println("解密: " + affineDecrypt(cipher, a, b));
        } catch (Exception e) {
            System.out.println("错误: " + e.getMessage());
        }
    }

    private static void testVigenereCipher(Scanner scanner) {
        System.out.print("输入明文: ");
        String plaintext = scanner.nextLine();
        System.out.print("输入密钥: ");
        String key = scanner.nextLine();

        String cipher = vigenereEncrypt(plaintext, key);
        System.out.println("密文: " + cipher);
        System.out.println("解密: " + vigenereDecrypt(cipher, key));
    }
}