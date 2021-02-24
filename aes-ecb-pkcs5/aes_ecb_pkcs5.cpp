#include "aes_ecb_pkcs5.h"

#include "ssl/sha.h"
#include "ssl/aes.h"

#include <string.h> // for strlen

// 将16进制字符串，转成字节数组
static void hex_str_to_byte(const char* source, unsigned char* dest, int sourceLen)
{
    short i;
    unsigned char highByte, lowByte;

    for (i = 0; i < sourceLen; i += 2)
    {
        highByte = toupper(source[i]);
        lowByte  = toupper(source[i + 1]);

        if (highByte > 0x39)
            highByte -= 0x37;
        else
            highByte -= 0x30;

        if (lowByte > 0x39)
            lowByte -= 0x37;
        else
            lowByte -= 0x30;

        dest[i / 2] = (highByte << 4) | lowByte;
    }
}

// 将字节数组，转成16进制字符串
static string byte_to_hex_string(const void* buf, size_t len)
{
    string ret;
    char tmp[8];
    const uint8_t* data = (const uint8_t*)buf;

    for (size_t i = 0; i < len; i += 16) {
        for (int j = 0; j < 16; ++j) {
            if (i + j < len) {
                int sz = sprintf(tmp, "%.2x", data[i + j]);
                ret.append(tmp, sz);
            }
        }
    }

    return ret;
}

// PKCS5填充
// 如果明文块少于16个字节（128bit），在明文块末尾补足相应数量的字符，且每个字节的值等于缺少的字符数。
// 比如明文：{1,2,3,4,5,a,b,c,d,e},缺少6个字节，则补全为{1,2,3,4,5,a,b,c,d,e,6,6,6,6,6,6 }
// 如果明文块等于16个字节，则继续填充16个字节16
// 如果明文块大于16个字节，按照16的整数倍计算还需填充多少字节，并进行填充对于的值
static void PKCS5_padding(unsigned char* src, int src_len)
{
    static const int padding_len = 16;
    if (src_len < padding_len) {
        unsigned char pad = padding_len - src_len;
        for (int i = padding_len; i > src_len; --i)
            src[i - 1] = pad;
    }
    else if (src_len == padding_len) {
        for (int i = padding_len; i < padding_len * 2; i++)
            src[i] = padding_len;
    }
    else {
        int pad = ((src_len + padding_len) / padding_len) * padding_len - src_len;
        for (int i = src_len; i < src_len+pad; i++)
            src[i] = pad;
    }
}

// 由于使用PKCS7Padding/PKCS5Padding填充时，最后一个字节肯定为填充数据的长度，
// 所以在解密后可以准确删除填充的数据，而使用ZeroPadding填充时，
// 没办法区分真实数据与填充数据，所以只适合以\0结尾的字符串加解密。
static int PKCS5_unpadding(char* in)
{
    int in_len = strlen(in);
    int pad, pad_len;
    pad = pad_len = in[in_len - 1];
    for (int i = 0; i < pad_len; ++i) {
        if (in[in_len - 1 - i] == pad)
            in[in_len - 1 - i] = 0;
    }
    return pad_len;
}

static int aes_encrypt(const char* in, size_t in_len, const char* key, char* out)
{
    if (!in || !key || !out) return -1;

    PKCS5_padding((unsigned char*)in, in_len);

    AES_KEY enc_key;
    if (AES_set_encrypt_key((const unsigned char*)key, strlen(key)*8, &enc_key) < 0)
        return -1;

    int len = strlen(in);
    int position = 0;

    while (position < len) {
        AES_ecb_encrypt((const unsigned char*)in+position, (unsigned char*)out+position, &enc_key, AES_ENCRYPT);
        position += AES_BLOCK_SIZE;
    }

    return position;
}

static int aes_decrypt(const char* in, size_t in_len, const char* key, char* out)
{
    if (!in || !key || !out) return -1;

    AES_KEY enc_key;
    if (AES_set_decrypt_key((const unsigned char*)key, 128, &enc_key) < 0)
        return -1;

    size_t position = 0;

    while (position < in_len) {
        AES_ecb_encrypt((const unsigned char*)in+position, (unsigned char*)out+position, &enc_key, AES_DECRYPT);
        position += AES_BLOCK_SIZE;
    }

    int pad_len = PKCS5_unpadding(out);
    return position - pad_len;
}

string aes_encrypt(const string& strData, const string& strKey)
{
    char key[AES_BLOCK_SIZE + 1] = {0};
    hex_str_to_byte(strKey.data(), (unsigned char*)key, strKey.length());

    char out[256] = {0};
    char in[256] = {0};
    memcpy(in, strData.data(), strData.length()); // 因为会进行pad处理必须单独分配空间

    int len = aes_encrypt(in, strData.length(), key, out);
    if (len == -1)
        return "";

    //size_t len = ((strData.length() + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    return byte_to_hex_string(out, len);
}

string aes_decrypt(const string& strData, const string& strKey)
{
    char data[256] = {0};
    hex_str_to_byte(strData.data(), (unsigned char*)data, strData.length());

    char key[AES_BLOCK_SIZE + 1] = {0};
    hex_str_to_byte(strKey.data(), (unsigned char*)key, strKey.length());

    // 若strData以00开头会有问题
    char out[256] = {0};
    int len = aes_decrypt(data, /*strlen(data)*/strData.length() / 2, key, out);
    if (len < 0)
        return "";

    return string(out, len);
}
