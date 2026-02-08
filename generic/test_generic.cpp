#include <windows.h>
#include "MemoryModule.hpp"

#include <iostream>
#include <vector>
#include <fstream>

typedef int (*AddNumbersProc)(int, int);

int main() {
    // 1. Ler o conteúdo da DLL para um buffer (vetor de bytes)
    std::ifstream dllFile("main.dll", std::ios::binary | std::ios::ate);
    if (!dllFile.is_open()) {
        std::cerr << "Erro ao abrir o arquivo DLL." << std::endl;
        return 1;
    }
    std::streamsize size = dllFile.tellg();
    dllFile.seekg(0, std::ios::beg);
    std::vector<char> buffer(size);
    if (!dllFile.read(buffer.data(), size)) {
        std::cerr << "Erro ao ler a DLL para a memória." << std::endl;
        return 1;
    }
    // 2. Carregar a DLL a partir do buffer de memória
    // Isso simula o Windows Loader (mapeamento de seções, importações, etc.)
    HMEMORYMODULE hModule = MemoryModule::MemoryLoadLibrary(buffer.data(), buffer.size());
    if (hModule == nullptr) {
        std::cerr << "Falha ao carregar a DLL via MemoryModule." << std::endl;
        return 1;
    }
    std::cout << "DLL carregada com sucesso na memoria!" << std::endl;
    // 3. Obter o endereço de uma função exportada
    AddNumbersProc addFunc = (AddNumbersProc)MemoryModule::MemoryGetProcAddress(hModule, "Somar");
    if (addFunc != nullptr) {
        // 4. Chamar a função
        int resultado = addFunc(10, 20);
        std::cout << "Resultado da funcao 'Somar' na DLL: " << resultado << std::endl;
    } else {
        std::cerr << "Funcao nao encontrada na DLL." << std::endl;
    }
    // 5. Liberar a biblioteca
    MemoryModule::MemoryFreeLibrary(hModule);
    return 0;
}