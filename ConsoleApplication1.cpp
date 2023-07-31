#include <Windows.h>
#include <iostream>

int main() {
    LPCWSTR sourceFile = L"C:\\Windows\\System32\\ntoskrnl.exe";
    LPCWSTR destinationFile = L"C:\\test.txt";

    // Obter as permiss�es do arquivo de origem (ntoskrnl.exe)
    PSECURITY_DESCRIPTOR pSecurityDescriptor = nullptr;
    DWORD bufferSize = 0;
    if (!GetFileSecurity(sourceFile, DACL_SECURITY_INFORMATION, nullptr, 0, &bufferSize) &&
        GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        pSecurityDescriptor = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, bufferSize);
        if (pSecurityDescriptor) {
            if (!GetFileSecurity(sourceFile, DACL_SECURITY_INFORMATION, pSecurityDescriptor, bufferSize, &bufferSize)) {
                std::cerr << "Erro ao obter as permiss�es do arquivo de origem." << std::endl;
                LocalFree(pSecurityDescriptor);
                return 1;
            }
        }
        else {
            std::cerr << "Erro ao alocar mem�ria para o descritor de seguran�a." << std::endl;
            return 1;
        }
    }
    else {
        std::cerr << "Erro ao obter as permiss�es do arquivo de origem." << std::endl;
        return 1;
    }

    // Aplicar as permiss�es ao arquivo de destino (test.txt)
    if (!SetFileSecurity(destinationFile, DACL_SECURITY_INFORMATION, pSecurityDescriptor)) {
        std::cerr << "Erro ao aplicar as permiss�es ao arquivo de destino." << std::endl;
        LocalFree(pSecurityDescriptor);
        return 1;
    }

    LocalFree(pSecurityDescriptor);
    std::cout << "Permiss�es copiadas com sucesso de ntoskrnl.exe para test.txt." << std::endl;
    return 0;
}
