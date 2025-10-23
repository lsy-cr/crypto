def rc4(data, key):
    # 第一步：初始化S盒（类似一个打乱的密码本）
    s = list(range(256))  # 初始化为0到255的列表
    j = 0
    key_len = len(key)
    
    # 用密钥打乱S盒
    for i in range(256):
        # 计算当前要交换的位置
        j = (j + s[i] + key[i % key_len]) % 256
        s[i], s[j] = s[j], s[i]  # 交换位置，打乱顺序
    
    # 第二步：生成密钥流并加密
    i = j = 0
    result = []
    for byte in data:
        # 不断更新位置
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]  # 再次打乱
        
        # 生成加密用的字节，与数据异或得到结果
        k = s[(s[i] + s[j]) % 256]
        result.append(byte ^ k)  # 异或操作：相同为0，不同为1
    
    return bytes(result)

# 使用示例
if __name__ == "__main__":
    # 准备密钥和明文（都要转成字节类型）
    key = "cipherByRC4".encode()  # 密钥
    plaintext = "abab".encode()  # 明文
    
    # 加密
    ciphertext = rc4(plaintext, key)
    print("加密后:", ciphertext.hex())  # 用十六进制显示密文
    
    # 解密（RC4加密解密用同一个函数）
    decrypted = rc4(ciphertext, key)
    print("解密后:", decrypted.decode())  # 转回字符串