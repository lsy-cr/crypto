from datetime import date
from click import group
from shapely import length
def keystream(initstate,period):
    key=[0]*period
    for i in range(len(initstate)):
        key[i]=initstate[i]
    for k in range(period-len(initstate)):
        key[5+k]=key[3+k]^key[k]
    return key    

def encrypt(text, key):
    if isinstance(text, str):
        btext = text.encode('utf-8')  # 字符串转字节
    else:
        btext = text  
    if len(text)*7>len(key):
        key+=key
    result = []  # 存储加密后的字节
    key_len = len(key)
    
    for byte in btext:  # 遍历每个明文字节
        # 取7位密钥（循环使用密钥流）
        key_group = []
        for i in range(7):
            # 密钥流索引：每次取7位，循环递增
            key_index = (len(result) * 7 + i) % key_len
            key_group.append(key[key_index])
        
        # 将7位密钥组转为整数（用于异或）
        key_int = int(''.join(map(str, key_group)), 2)
        # 字节与密钥异或（加密核心）
        encrypted_byte = byte ^ key_int
        result.append(encrypted_byte)
    
    return bytes(result)


if __name__ == "__main__":
    initstate = [1, 1, 0, 0, 1]  # 初始状态（文档默认）
    period = 31  # 周期（文档规定）
    text1 = "abcabcabcabc"  # 明文
    
    keys = keystream(initstate, period)  # 生成密钥流
    ciphertext = encrypt(text1, keys)  # 加密
    
    # 输出结果（密文可能含不可见字符，用bytes形式展示）
    print(f"明文: {text1}")
    print(f"密文（bytes）: {ciphertext}")
    print(f"密文（字符串）: {ciphertext.decode('utf-8', errors='replace')}")

