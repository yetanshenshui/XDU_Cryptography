def validate_and_strip_pkcs7(data):
    # 验证并去除 PKCS#7 填充
    if not data:
        raise ValueError("数据为空")

    pad_length = data[-1]

    # 验证填充长度和内容
    if pad_length < 1 or pad_length > len(data) or data[-pad_length:] != bytes([pad_length]) * pad_length:
        raise ValueError("无效的PKCS#7填充")

    return data[:-pad_length]


# 使用示例
if __name__ == "__main__":
    # 有效填充
    valid_data = b"ICE ICE BABY\x04\x04\x04\x04"
    result = validate_and_strip_pkcs7(valid_data)
    print(f"有效填充结果: {result}")

    # 无效填充
    invalid_data1 = b"ICE ICE BABY\x05\x05\x05\x05"
    invalid_data2 = b"ICE ICE BABY\x01\x02\x03\x04"
    try:
        validate_and_strip_pkcs7(invalid_data1)
    except ValueError as e:
        print(f"无效填充错误: {e}")
    try:
        validate_and_strip_pkcs7(invalid_data2)
    except ValueError as e:
        print(f"无效填充错误: {e}")