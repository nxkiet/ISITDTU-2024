//      g++ chall.cpp -o chall -std=c++17 -s -lssl -lcrypto -I /usr/local/opt/openssl/include -L /usr/local/opt/openssl/lib -I include/**/*.c

#include <algorithm>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <stdlib.h>
#include <fstream>
#include <filesystem>
#include <random>
#include <regex>
#include <unordered_set>
#include <random>
#include <ctime>
#include <chrono>
#include <openssl/ssl.h>
#include "include/base64.h"
#include "include/sha256/sha256.h"

struct license_file
{
    std::string key;
    std::string iv;
};

inline std::string unhex(const std::string &str)
{
    if (str.size() % 2 != 0)
        throw std::invalid_argument("Hex string must have an even length.");

    std::string bytes;
    bytes.reserve(str.size() / 2); // Reserve enough space for efficiency.

    for (size_t i = 0; i < str.size(); i += 2)
    {
        unsigned int byte;
        // Parse two characters as a hex byte.
        if (std::sscanf(str.c_str() + i, "%2x", &byte) != 1)
            throw std::invalid_argument("Invalid hex character in string.");

        bytes.push_back(static_cast<char>(byte));
    }

    return bytes;
}

std::string decode_license_file(const std::string cert)
{
    int size;
    auto dec = unbase64(cert.c_str(), cert.size(), &size);
    std::string str(dec, dec + size);
    free(dec);
    return str;
}

// Parese json
license_file parse_json(const std::string &json_str)
{
    license_file license;

    // Remove spaces for simplicity
    std::string json = json_str;
    json.erase(remove(json.begin(), json.end(), ' '), json.end());

    // Find keys and values
    std::size_t key_pos = json.find("\"key\"");
    std::size_t iv_pos = json.find("\"iv\"");

    if (key_pos != std::string::npos)
    {
        std::size_t start = json.find(':', key_pos) + 1;
        std::size_t end = json.find(',', key_pos);
        license.key = json.substr(start + 1, end - start - 2); // Remove quotes
    }

    if (iv_pos != std::string::npos)
    {
        std::size_t start = json.find(':', iv_pos) + 1;
        std::size_t end = json.find('}', iv_pos);
        license.iv = json.substr(start + 1, end - start - 2); // Remove quotes
    }

    return license;
}

license_file import_license_file(const std::string path)
{
    license_file lic{};

    // Read path
    std::stringstream buf;
    std::ifstream f(path);
    buf << f.rdbuf();
    auto enc = buf.str();
    if (enc.empty())
    {
        std::cerr << "Failed to read license file" << std::endl;
        return lic;
    }

    // Decode contents
    auto dec = decode_license_file(enc);
    if (dec.empty())
    {
        // std::cerr << "Failed to decode license file" << std::endl;
        return lic;
    }

    // Parse JSON;
    lic = parse_json(dec);
    return lic;
}

std::string decrypt_license_file(const std::string &cp, license_file lic)
{
    // std::cout << cp;
    // hash key
    uint8_t key_bytes[32];
    sha256_easy_hash(lic.key.c_str(), lic.key.size(), key_bytes);

    // Convert to bytes
    int iv_size;
    int plaintext_len = 0;
    int final_len = 0;
    int ciphertext_size;

    auto ciphertext = unbase64(cp.c_str(), cp.size(), &ciphertext_size);
    auto iv_bytes = reinterpret_cast<const unsigned char *>(lic.iv.c_str());
    auto plaintext = new unsigned char[ciphertext_size];

    // Initialize AES
    auto cipher = EVP_aes_256_cbc();
    auto ctx = EVP_CIPHER_CTX_new();

    // Decrypt
    auto status = EVP_DecryptInit_ex(ctx, cipher, nullptr, key_bytes, iv_bytes);
    if (status == 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        delete[] plaintext;
        return "";
    }

    status = EVP_DecryptUpdate(ctx, plaintext, &plaintext_len, ciphertext, ciphertext_size);
    if (status == 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        delete[] plaintext;
        return "";
    }

    // Finalize
    EVP_DecryptFinal_ex(ctx, plaintext + plaintext_len, &final_len);
    EVP_CIPHER_CTX_free(ctx);

    // Convert plaintext to string
    plaintext_len += final_len;
    std::string out(reinterpret_cast<char *>(plaintext), plaintext_len);
    delete[] plaintext;

    return out;
}

void showflag(const std::string &username)
{

    std::ifstream file;

    std::string path = "storage/" + username + ".txt";
    file.open(path);
    if (!file.is_open())
    {
        std::cerr << "Failed to open file" << std::endl;
        return;
    }
    std::string line;
    while (std::getline(file, line))
    {
        if (line.find("Drink:") == 0)
        {
            std::cout << "Drink: " << line.substr(6) << std::endl;
            break;
        }
    }
    file.close();
}

void printOrder(bool check, const std::string &username)
{
    if (check == true)
    {
        std::cout << "Here your drink\n";
        showflag(username);
    }
    else
    {
        std::cout << "Here your drink\n"
                  << "Hmmm nope -.-\n";
    }
}

// void CheckCoffe(std::string inp, const std::string &username)
// {
//     try
//     {
//         int size;
//         auto dec = unbase64(inp.c_str(), inp.size(), &size);
//         std::string str((char *)dec);
//         std::string decoded = unhex(str);
//         printOrder(decoded.find("BrownCoffe") != std::string::npos ? true : false, username);
//     }
//     catch (const std::exception &e)
//     {
//         printOrder(false, username);
//     }
// }

// void CheckSoda(std::string inp, const std::string &username)
// {
//     auto now = std::chrono::system_clock::now();
//     std::time_t now_time = std::chrono::system_clock::to_time_t(now);
//     std::tm local_tm = *std::localtime(&now_time);
//     int seed = (local_tm.tm_hour * 60 + local_tm.tm_min) / 5;
//     std::mt19937 eng(seed);

//     int sizet;
//     auto dec = unbase64(inp.c_str(), inp.size(), &sizet);

//     std::string result(sizet, '\0');
//     for (size_t i = 0; i < sizet; ++i)
//     {
//         std::uniform_int_distribution<unsigned char> dist(0, 255);
//         unsigned char randomByte = dist(eng);
//         result[i] = dec[i] ^ randomByte;
//     }

//     printOrder(result.find("S0da_Bluee") != std::string::npos ? true : false, username);
// }

void CheckSeaDrink(std::string cp, license_file lic, const std::string &username)
{
    // random seed
    auto now = std::chrono::system_clock::now();
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);
    std::tm local_tm = *std::localtime(&now_time);
    int seed = (local_tm.tm_hour * 60 + local_tm.tm_min) / 5;
    std::mt19937 eng(seed);

    std::string dec = decrypt_license_file(cp, lic);

    std::string result(dec.size(), '\0');
    for (size_t i = 0; i < dec.size(); ++i)
    {
        std::uniform_int_distribution<unsigned char> dist(0, 255);
        unsigned char randomByte = dist(eng);
        result[i] = dec[i] ^ randomByte;
    }

    // remove duplicate
    std::string input = result;
    std::unordered_set<char> chars;

    input.erase(
        std::remove_if(
            input.begin(),
            input.end(),
            [&chars](char i)
            {
                if (chars.count(i))
                {
                    return true;
                }
                chars.insert(i);
                return false;
            }),
        input.end());
    printOrder(input.find("Se@_C0ckTa1l") != std::string::npos ? true : false, username);
}

bool Login(std::string &name)
{
    std::string pwd, fileName, storedPass;
    std::cout << "Username: ";
    std::cin >> name;
    std::cout << "Password: ";
    std::cin >> pwd;

    fileName = "storage/" + name + ".txt";
    if (std::filesystem::exists(fileName))
    {
        // Open the file for reading
        std::ifstream file(fileName);
        if (!file.is_open())
        {
            std::cerr << "Error opening file for user " << name << ".\n";
            return false;
        }
        std::string prefix;
        file >> prefix >> storedPass;
        file.close();

        if (pwd == storedPass)
        {
            std::cout << "Login successful.\n";
            return true;
        }
        else
        {
            std::cout << "Error: Incorrect password.\n";
            return false;
        }
    }
    else
    {
        std::cout << "Error: User " << name << " does not exist.\n";
        return false;
    }
}
void AddUserToFile(const std::string &username, const std::string &password, const std::string &description)
{
    std::string fileName = "storage/" + username + ".txt";

    try
    {
        std::ofstream file(fileName);
        if (!file.is_open())
        {
            throw std::ios_base::failure("Failed to open file.");
        }

        // Write user data to the file
        file << "Password: " << password << "\n";
        file << "Drink: " << description << "\n";

        // Close the file
        file.close();

        std::cout << "Register successful\n";
    }
    catch (const std::exception &e)
    {
        std::cerr << "Exception occurred: " << e.what() << "\n";
    }
}

void Register()
{
    std::string name, pass, description;

    std::cout << "Username: ";
    std::cin >> name;
    std::cout << "Password: ";
    std::cin >> pass;
    std::cout << "Drink: ";
    std::cin.ignore();
    std::getline(std::cin, description);

    AddUserToFile(name, pass, description);
}

void menu(const std::string name)
{
    // get license.lic
    std::string path = "ingredients";

    auto lic = import_license_file(path);
    if (lic.key.empty() or lic.iv.empty())
    {
        std::cerr << "Ingredients is sold out" << std::endl;
        return;
    }

    std::string cp;
    char chs = '0';

    while (chs != '2')
    {
        std::cout << "\n1: Order\n"
                  << "2: Quit\n"
                  << "Enter: ";
        std::cin >> chs;
        if (chs == '1')
        {
            std::cout << "\nEnter Drink: ";
            std::cin >> cp;
            CheckSeaDrink(cp, lic, name);
        }
    }

    // while (1)
    // {
    //     std::cout << "\n~~Menu~~\n"
    //               << "1: 0xC0ffee\n"
    //               << "2: Xoda\n"
    //               << "3: SeaDrink\n"
    //               << "4: Exit\n"
    //               << "\nEnter: ";
    //     std::cin >> chs;

    //     switch (chs)
    //     {
    //     case '1':
    //     {
    //         std::cout << "\nWhat kind of 0xC0ffee do you drink? ";
    //         std::cin >> cp;
    //         CheckCoffe(cp, name);
    //         break;
    //     }
    //     case '2':
    //     {
    //         std::cout << "\nWhat kind of Xoda do you drink? ";
    //         std::cin >> cp;
    //         CheckSoda(cp, name);
    //         break;
    //     }
    //     case '3':
    //     {
    //         std::cout << "\nWhat kind of SeaDrink do you drink? ";
    //         std::cin >> cp;
    //         CheckSeaDrink(cp, lic, name);
    //         break;
    //     }
    //     case '4':
    //     {
    //         std::cout << "\nSee you later\n";
    //         return;
    //     }
    //     default:
    //         std::cout << "Invalid options\n";
    //         break;
    //     }
    // }
}

int main(int argc, char *argv[])
{
    while (1)
    {
        std::cout << "\n~~VIP ACCOUNT~~\n"
                  << "1: Login VIP\n"
                  << "2: Register VIP\n"
                  << "3: Exit\n"
                  << "Enter: ";
        char a;
        std::cin >> a;
        switch (a)
        {
        case '1':
        {
            std::string name;
            if (Login(name))
                menu(name);
            break;
        }
        case '2':
        {
            Register();
            break;
        }
        case '3':
        {
            std::cout << "\nSee you later\n";
            return 0;
        }
        default:
            break;
        }
    }
    return 0;
}