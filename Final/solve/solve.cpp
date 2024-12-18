// g++ AES_test.cpp -o AES_test -std=c++17 -s -lssl -lcrypto -I /usr/local/opt/openssl/include -L /usr/local/opt/openssl/lib -I ../service/src/include/**/*.c

#include <iostream>
#include <string>
#include <fstream>
#include <ctime>
#include <chrono>
#include <random>
#include <openssl/evp.h>
#include "../service/src/include/sha256/sha256.h"
#include "../service/src/include/base64.h"

std::string AES_enc(const std::string &pl, const std::string &key, const std::string &iv_str)
{
    // Hash the key with SHA-256
    uint8_t key_bytes[32];
    sha256_easy_hash(key.c_str(), key.size(), key_bytes);

    // Convert iv_str to unsigned char*
    auto iv = reinterpret_cast<const unsigned char *>(iv_str.c_str());

    // Allocate memory for ciphertext
    int ciphertext_len = 0;
    int final_len = 0;
    int max_ciphertext_len = pl.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc());
    auto ciphertext = new unsigned char[max_ciphertext_len];

    // Encryption context
    auto ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        std::cerr << "Failed to create EVP_CIPHER_CTX" << std::endl;
        return "";
    }

    // Initialize encryption
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key_bytes, iv) != 1)
    {
        std::cerr << "EVP_EncryptInit_ex failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        delete[] ciphertext;
        return "";
    }

    // Encrypt the plaintext
    if (EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, reinterpret_cast<const unsigned char *>(pl.c_str()), pl.size()) != 1)
    {
        std::cerr << "EVP_EncryptUpdate failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        delete[] ciphertext;
        return "";
    }

    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &final_len) != 1)
    {
        std::cerr << "EVP_EncryptFinal_ex failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        delete[] ciphertext;
        return "";
    }

    // Clean up
    ciphertext_len += final_len;
    EVP_CIPHER_CTX_free(ctx);

    // Convert ciphertext to std::string
    std::string encrypted(reinterpret_cast<char *>(ciphertext), ciphertext_len);
    delete[] ciphertext;

    return encrypted;
}

std::string AES_dec(const std::string &ciphertext, const std::string &key, const std::string &iv_str)
{
    // Hash the key with SHA-256
    uint8_t key_bytes[32];
    sha256_easy_hash(key.c_str(), key.size(), key_bytes);

    // Convert iv_str to unsigned char*
    auto iv = reinterpret_cast<const unsigned char *>(iv_str.c_str());
    auto cp = reinterpret_cast<const unsigned char *>(ciphertext.c_str());

    // Allocate memory for plaintext
    int plaintext_len = 0;
    int final_len = 0;
    auto plaintext = new unsigned char[ciphertext.size()];

    // Decryption context
    auto ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        std::cerr << "Failed to create EVP_CIPHER_CTX" << std::endl;
        return "";
    }

    // Initialize decryption
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key_bytes, iv) != 1)
    {
        std::cerr << "EVP_DecryptInit_ex failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        delete[] plaintext;
        return "";
    }

    // Decrypt the ciphertext
    if (EVP_DecryptUpdate(ctx, plaintext, &plaintext_len, cp, ciphertext.size()) != 1)
    {
        std::cerr << "EVP_DecryptUpdate failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        delete[] plaintext;
        return "";
    }

    // Finalize decryption
    if (EVP_DecryptFinal_ex(ctx, plaintext + plaintext_len, &final_len) != 1)
    {
        std::cerr << "EVP_DecryptFinal_ex failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        delete[] plaintext;
        return "";
    }

    // Clean up
    plaintext_len += final_len;
    EVP_CIPHER_CTX_free(ctx);

    // Convert plaintext to std::string
    std::string decrypted(reinterpret_cast<char *>(plaintext), plaintext_len);
    // std::cout << plaintext << "\t" << plaintext_len << "\n";
    delete[] plaintext;

    return decrypted;
}

int main()
{
    auto now = std::chrono::system_clock::now();
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);
    std::tm local_tm = *std::localtime(&now_time);
    int seed = (local_tm.tm_hour * 60 + local_tm.tm_min) / 5;
    std::mt19937 eng(seed);

    std::string plaintext = "Se@_C0ckTa1l";
    // std::cout << "Enter: ";
    // std::cin >> plaintext;

    std::string key = "we1c0me_t0_DaNang_VietNam";
    std::string iv = "b0aeb525349a40a401ea547d9c73d026";
    std::string out;

    // std::string result(dec.size() - 1, '\0');

    for (size_t i = 0; i < plaintext.size(); ++i)
    {
        std::uniform_int_distribution<unsigned char> dist(0, 255);
        unsigned char randomByte = dist(eng);
        result[i] = plaintext[i] ^ randomByte;
    }

    std::string encrypted = AES_enc(result, key, iv);

    std::string license;
    int ens, lcs;

    license += "{\"key\":\"" + key + "\", \"iv\":\"" + iv + "\"}";
    std::string hehe = (std::string)base64(license.c_str(), license.size(), &lcs);

    std::cout << (std::string)base64(encrypted.c_str(), encrypted.size(), &ens) << "\n";
    // std::cout << license << std::endl;

    // write license.lic
    std::ofstream file;
    file.open("../service/src/ingredients");
    if (!file.is_open())
    {
        std::cerr << "Failed to open file" << std::endl;
    }
    file << hehe;
    // std::cout << "Ingredients has been written to file ingredients" << std::endl;
    file.close();

    // decrypt
    std::string decrypted = AES_dec(encrypted, key, iv);
    if (!decrypted.empty())
    {
        // std::cout << "Decrypted plaintext: " << decrypted << "\t" << decrypted.size() << std::endl;
    }
    else
    {
        std::cerr << "Decryption failed." << std::endl;
        return 1;
    }

    return 0;
}
