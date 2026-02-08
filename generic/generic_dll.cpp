#include <windows.h>
#include <Commdlg.h>
#include <winnt.h>
#include <imagehlp.h>
#include <vector>
#include <string>
#include <fstream>
#include <tchar.h>
#include <stdio.h>
#include <iomanip>
#include <iostream>

#include "MemoryModule.hpp"


extern "C" {
    __declspec(dllexport) void MinhaFuncao() {
        MessageBoxA(NULL, "Olá! Fui chamada de dentro da DLL via MemoryModule!", "Sucesso", MB_OK);
    }

    __declspec(dllexport) int Somar(int a, int b) {
        return a + b;
    }
}

void listDLLFunctions(std::string sADllName, std::vector<std::string> &slListOfDllFunctions) {
    DWORD *dNameRVAs(0);
    _IMAGE_EXPORT_DIRECTORY *ImageExportDirectory;
    unsigned long cDirSize;
    _LOADED_IMAGE LoadedImage;
    std::string sName;
    slListOfDllFunctions.clear();
    if (MapAndLoad(sADllName.c_str(), NULL, &LoadedImage, TRUE, TRUE))
    {
        ImageExportDirectory = (_IMAGE_EXPORT_DIRECTORY *)ImageDirectoryEntryToData(LoadedImage.MappedAddress, false, IMAGE_DIRECTORY_ENTRY_EXPORT, &cDirSize);
        if (ImageExportDirectory != NULL)
        {
            dNameRVAs = (DWORD *)ImageRvaToVa(LoadedImage.FileHeader, LoadedImage.MappedAddress, ImageExportDirectory->AddressOfNames, NULL);

            for (size_t i = 0; i < ImageExportDirectory->NumberOfNames; i++)
            {
                sName = (char *)ImageRvaToVa(LoadedImage.FileHeader, LoadedImage.MappedAddress, dNameRVAs[i], NULL);
                slListOfDllFunctions.push_back(sName);
            }
        }
        UnMapAndLoad(&LoadedImage);
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    //preciso de um endereço para copiar
	switch (ul_reason_for_call)
	{
        case DLL_PROCESS_ATTACH:
        {
            std::string dllAbsolutePath = "E:\\repos\\BAD_BOY\\dll_proxy\\generic\\main.dll";
            std::vector<std::string> names;
            listDLLFunctions(dllAbsolutePath, names);

            for (int i = 0; i < names.size(); i++) {
                std::cout << "function " << i << ": " << names[i] << "\n";
            }

            printf("DLL carregada no endereco: %p\n", (void*)hModule);
            break;
        }
        case DLL_PROCESS_DETACH:
        {
            
            break;
        }
	}
	return TRUE;
}