#include <iostream>
#include <string>
#include <windows.h>

bool check(const std::string &str)
{

    unsigned char _code_raw[] = {0x74, 0x03, 0x75, 0x01, 0xe8, 0x48, 0x89, 0x5C, 0x24, 0x18, 0x48, 0x89, 0x6C, 0x24, 0x20, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x44, 0x0F, 0xBE, 0x59, 0x19, 0x4C, 0x8B, 0xC1, 0x0F, 0xBE, 0x59, 0x1B, 0x41, 0x8B, 0xD3, 0x0F, 0xBE, 0x71, 0x01, 0x44, 0x0F, 0xBE, 0x71, 0x20, 0x8B, 0xC6, 0x0F, 0xBE, 0x69, 0x08, 0x44, 0x0F, 0xBE, 0x49, 0x1D, 0x0F, 0xAF, 0xD3, 0x0F, 0xAF, 0xC5, 0x41, 0x0F, 0xAF, 0xD6, 0x03, 0xD0, 0x41, 0x2B, 0xD1, 0x81, 0xFA, 0x72, 0x38, 0x08, 0x00, 0x0F, 0x85, 0x88, 0x02, 0x00, 0x00, 0x0F, 0xBE, 0x51, 0x04, 0x44, 0x0F, 0xBE, 0x61, 0x0A, 0x8B, 0xC2, 0x44, 0x0F, 0xBE, 0x79, 0x14, 0x44, 0x0F, 0xBE, 0x51, 0x0B, 0x0F, 0xBE, 0x49, 0x06, 0x41, 0x0F, 0xBE, 0x78, 0x07, 0x41, 0x0F, 0xAF, 0xC4, 0x41, 0x0F, 0xAF, 0xC7, 0x2B, 0xC1, 0x41, 0x2B, 0xC2, 0x03, 0xC7, 0x3D, 0x1A, 0x27, 0x0A, 0x00, 0x0F, 0x85, 0x50, 0x02, 0x00, 0x00, 0x41, 0x0F, 0xBE, 0x40, 0x10, 0x41, 0x0F, 0xBE, 0x78, 0x1E, 0xFF, 0xC8, 0x45, 0x0F, 0xBE, 0x68, 0x16, 0x41, 0x0F, 0xBE, 0x48, 0x1F, 0x45, 0x0F, 0xBE, 0x50, 0x0E, 0x0F, 0xAF, 0xC8, 0x44, 0x0F, 0xAF, 0xEF, 0x41, 0x2B, 0xCD, 0x41, 0x03, 0xCA, 0x81, 0xF9, 0x7F, 0xF4, 0xFF, 0xFF, 0x0F, 0x85, 0x1C, 0x02, 0x00, 0x00, 0x41, 0x0F, 0xBE, 0x48, 0x09, 0x41, 0x0F, 0xBE, 0x40, 0x03, 0x45, 0x0F, 0xBE, 0x68, 0x12, 0x2B, 0xC1, 0x41, 0x0F, 0xBE, 0x48, 0x0B, 0x41, 0x2B, 0xC5, 0x45, 0x0F, 0xBE, 0x50, 0x21, 0x2B, 0xC1, 0x2B, 0xC2, 0x41, 0x03, 0xC2, 0x3D, 0x41, 0xFF, 0xFF, 0xFF, 0x0F, 0x85, 0xEC, 0x01, 0x00, 0x00, 0x45, 0x0F, 0xAF, 0xCB, 0x44, 0x2B, 0xCD, 0x45, 0x03, 0xCD, 0x44, 0x03, 0xCF, 0x44, 0x03, 0xCE, 0x41, 0x81, 0xF9, 0xF5, 0x12, 0x00, 0x00, 0x0F, 0x85, 0xCF, 0x01, 0x00, 0x00, 0x45, 0x0F, 0xBE, 0x58, 0x17, 0x41, 0x0F, 0xBE, 0x40, 0x0E, 0x41, 0x0F, 0xBE, 0x48, 0x02, 0x41, 0x0F, 0xBE, 0x78, 0x07, 0x45, 0x0F, 0xBE, 0x48, 0x05, 0x41, 0x0F, 0xAF, 0xCB, 0x45, 0x0F, 0xBE, 0x58, 0x0D, 0x0F, 0xAF, 0xC8, 0x41, 0x8B, 0xC1, 0x0F, 0xAF, 0xCF, 0x2B, 0xC1, 0x41, 0x03, 0xC3, 0x3D, 0x97, 0x67, 0xDD, 0xFA, 0x0F, 0x85, 0x94, 0x01, 0x00, 0x00, 0x41, 0x0F, 0xBE, 0x40, 0x0C, 0x41, 0x8B, 0xCC, 0x41, 0x0F, 0xAF, 0xC1, 0x45, 0x0F, 0xBE, 0x48, 0x09, 0x0F, 0xAF, 0xCB, 0x41, 0x0F, 0xAF, 0xC1, 0x41, 0x03, 0xC3, 0x03, 0xC8, 0x81, 0xF9, 0xD2, 0x54, 0x0D, 0x00, 0x0F, 0x85, 0x6B, 0x01, 0x00, 0x00, 0x41, 0x0F, 0xBE, 0x48, 0x15, 0x45, 0x0F, 0xBE, 0x58, 0x03, 0x8B, 0xC1, 0x41, 0x0F, 0xAF, 0xC1, 0x45, 0x0F, 0xBE, 0x48, 0x06, 0x41, 0x0F, 0xAF, 0xC5, 0x45, 0x0F, 0xBE, 0x68, 0x16, 0x41, 0x2B, 0xC1, 0x41, 0x03, 0xC3, 0x41, 0x03, 0xC5, 0x3D, 0x3C, 0xE4, 0x06, 0x00, 0x0F, 0x85, 0x39, 0x01, 0x00, 0x00, 0x41, 0x0F, 0xBE, 0x40, 0x17, 0x45, 0x0F, 0xBE, 0x58, 0x18, 0x41, 0x0F, 0xBE, 0x58, 0x22, 0x41, 0x0F, 0xAF, 0xC6, 0x2B, 0xC2, 0x41, 0x03, 0xC3, 0x03, 0xC3, 0x03, 0xC1, 0x3D, 0x86, 0x24, 0x00, 0x00, 0x0F, 0x85, 0x12, 0x01, 0x00, 0x00, 0x45, 0x0F, 0xBE, 0x70, 0x1A, 0x41, 0x0F, 0xBE, 0x50, 0x23, 0x41, 0x0F, 0xBE, 0x58, 0x11, 0x41, 0x0F, 0xBE, 0x48, 0x13, 0x8B, 0xC3, 0x2B, 0xC1, 0x89, 0x54, 0x24, 0x40, 0x41, 0x2B, 0xC6, 0x44, 0x89, 0x74, 0x24, 0x38, 0x41, 0x2B, 0xC1, 0x03, 0xC2, 0x41, 0x03, 0xC3, 0x83, 0xF8, 0x1B, 0x0F, 0x85, 0xDD, 0x00, 0x00, 0x00, 0x41, 0x0F, 0xBE, 0x50, 0x17, 0x8B, 0xC1, 0x45, 0x0F, 0xBE, 0x58, 0x0F, 0x0F, 0xAF, 0xC2, 0x41, 0x0F, 0xBE, 0x50, 0x03, 0x2B, 0xC2, 0x41, 0x0F, 0xBE, 0x50, 0x0D, 0x41, 0x03, 0xC3, 0x03, 0xC2, 0x41, 0x0F, 0xBE, 0x50, 0x0E, 0x03, 0xC2, 0x3D, 0xEF, 0x2B, 0x00, 0x00, 0x0F, 0x85, 0xAB, 0x00, 0x00, 0x00, 0x45, 0x0F, 0xBE, 0x70, 0x0C, 0x41, 0x0F, 0xBE, 0x50, 0x15, 0x41, 0x8B, 0xC6, 0x0F, 0xAF, 0xC7, 0x41, 0x0F, 0xBE, 0x78, 0x02, 0x41, 0x2B, 0xC3, 0x2B, 0xC2, 0x03, 0xC3, 0x03, 0xC7, 0x3D, 0xF1, 0x33, 0x00, 0x00, 0x0F, 0x85, 0x82, 0x00, 0x00, 0x00, 0x41, 0x0F, 0xBE, 0x50, 0x1C, 0x45, 0x0F, 0xBE, 0x08, 0x8B, 0xC2, 0x41, 0x2B, 0xC1, 0x41, 0x2B, 0xC7, 0x03, 0x44, 0x24, 0x38, 0x03, 0x44, 0x24, 0x40, 0x03, 0xC5, 0x3D, 0x0A, 0x01, 0x00, 0x00, 0x75, 0x60, 0x41, 0x0F, 0xAF, 0xD6, 0x2B, 0xD6, 0x41, 0x03, 0xD1, 0x03, 0xD3, 0x03, 0xD7, 0x81, 0xFA, 0xB6, 0x28, 0x00, 0x00, 0x75, 0x4B, 0x41, 0x0F, 0xBE, 0x40, 0x05, 0x0F, 0xAF, 0xC8, 0x41, 0x0F, 0xBE, 0x40, 0x22, 0x2B, 0xC8, 0x41, 0x0F, 0xBE, 0x40, 0x0B, 0x2B, 0xC8, 0x41, 0x03, 0xCB, 0x41, 0x03, 0xCD, 0x81, 0xF9, 0x9B, 0x26, 0x00, 0x00, 0x75, 0x27, 0x41, 0x0F, 0xBE, 0x40, 0x10, 0xB9, 0x01, 0x00, 0x00, 0x00, 0x41, 0x2B, 0xCF, 0x45, 0x0F, 0xAF, 0xD4, 0x0F, 0xAF, 0xC8, 0x33, 0xC0, 0x41, 0x03, 0xCA, 0x41, 0x2B, 0xC9, 0x81, 0xF9, 0x1C, 0xEA, 0xFF, 0xFF, 0x0F, 0x94, 0xC0, 0xEB, 0x02, 0x33, 0xC0, 0x48, 0x8B, 0x5C, 0x24, 0x48, 0x48, 0x8B, 0x6C, 0x24, 0x50, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x5F, 0x5E, 0xC3};
    typedef int (*_code_t)(const char *);

    DWORD old_flag;
    VirtualProtect(_code_raw, sizeof _code_raw, PAGE_EXECUTE_READWRITE, &old_flag);
    _code_t fn_code = (_code_t)(void *)_code_raw;

    const char *val = str.c_str();
    int res = fn_code(val);
    if (res == 1)
    {
        return true;
    }
    return false;
}

bool animal(std::string &str)
{
    const char *animals[] = {
        "dog",
        "bat",
        "fox",
        "ant",
        "cat",
        "cow",
        "pig",
        "rat"};

    std::string substring;
    substring += str[17];
    substring += str[18];
    substring += str[19];

    if (substring != animals[4])
    {
        return false;
    }
    return true;
}

int main()
{
    std::string flag = "";
    std::cout << "Enter the flag: ";
    std::cin >> flag;

    if (flag.length() == 36 && flag[33] == flag[34] && flag[8] * 2 == 194 && animal(flag) && check(flag))
    {
        std::cout << "True!!";
    }
    else
    {
        std::cout << "False!!";
    }
    return 0;
}