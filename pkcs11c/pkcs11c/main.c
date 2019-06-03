#include <cstdio>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>


int main()
{
    printf("Hello world!\n");
    return 0;
}

int C_Encrypt(  long hSession,	/* the session's handle */
                byte *ptr pData,	/* the plaintext data */
                long ulDataLen,	/* bytes of plaintext data */
                CK_BYTE_PTR pEncryptedData,	/* receives encrypted data */
                CK_ULONG_PTR pulEncryptedDataLen)
{


}

std::string exec(const char* cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}
