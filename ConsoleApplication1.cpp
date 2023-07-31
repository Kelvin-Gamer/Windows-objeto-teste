#include <Windows.h>
#include <iostream>

int main() {
    LPCWSTR sourceFile = L"C:\\Windows\\System32\\ntoskrnl.exe";
    LPCWSTR destinationFile = L"C:\\test.txt";

    // Obter as permissões do arquivo de origem (ntoskrnl.exe)
    PSECURITY_DESCRIPTOR pSecurityDescriptor = nullptr;
    DWORD bufferSize = 0;
    if (!GetFileSecurity(sourceFile, DACL_SECURITY_INFORMATION, nullptr, 0, &bufferSize) &&
        GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        pSecurityDescriptor = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, bufferSize);
        if (pSecurityDescriptor) {
            if (!GetFileSecurity(sourceFile, DACL_SECURITY_INFORMATION, pSecurityDescriptor, bufferSize, &bufferSize)) {
                std::cerr << "Erro ao obter as permissões do arquivo de origem." << std::endl;
                LocalFree(pSecurityDescriptor);
                return 1;
            }
        }
        else {
            std::cerr << "Erro ao alocar memória para o descritor de segurança." << std::endl;
            return 1;
        }
    }
    else {
        std::cerr << "Erro ao obter as permissões do arquivo de origem." << std::endl;
        return 1;
    }

    // Aplicar as permissões ao arquivo de destino (test.txt)
    if (!SetFileSecurity(destinationFile, DACL_SECURITY_INFORMATION, pSecurityDescriptor)) {
        std::cerr << "Erro ao aplicar as permissões ao arquivo de destino." << std::endl;
        LocalFree(pSecurityDescriptor);
        return 1;
    }

    LocalFree(pSecurityDescriptor);
    std::cout << "Permissões copiadas com sucesso de ntoskrnl.exe para test.txt." << std::endl;
    return 0;
}
