#ifndef AES_ECB_H
#define AES_ECB_H

#include <string>

using std::string;

string aes_encrypt(const string& strData, const string& strKey);
string aes_decrypt(const string& strData, const string& strKey);

#endif // AES_ECB_H
