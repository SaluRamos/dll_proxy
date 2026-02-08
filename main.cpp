#include <iostream>
#include <Windows.h>
#include <Commdlg.h>
#include <String.h>
#include <winnt.h>
#include <imagehlp.h>
#include <vector>
#include <string>
#include <fstream>
#include <tchar.h>
#include <stdio.h>
#include <iomanip>
#include <iostream>

using namespace std;

struct RawFile {
    LPVOID data;
    DWORD size;
};

RawFile GetFileContent(const char* lpFilePath) {
	RawFile result = { nullptr, 0 };
	// Abre o arquivo
    HANDLE hFile = CreateFileA(lpFilePath, GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("[-] Erro ao abrir o arquivo PE!\n");
        return result;
    }
    // Pega o tamanho real
    DWORD dFileSize = GetFileSize(hFile, nullptr);
    if (dFileSize == INVALID_FILE_SIZE)
    {
        printf("[-] Erro ao ler tamanho do arquivo!\n");
        CloseHandle(hFile);
        return result;
    }
    // Aloca a memória exata necessária
    LPVOID hFileContent = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dFileSize);
    if (hFileContent == nullptr)
    {
        printf("[-] Erro de alocacao de memoria!\n");
        CloseHandle(hFile);
        return result;
    }
    // Lê o arquivo para a memória
    DWORD bytesRead = 0;
    BOOL bFileRead = ReadFile(hFile, hFileContent, dFileSize, &bytesRead, nullptr);
    if (!bFileRead || bytesRead != dFileSize)
    {
        printf("[-] Erro ao ler o conteudo do arquivo!\n");
        HeapFree(GetProcessHeap(), 0, hFileContent); // Limpa se falhar
        CloseHandle(hFile);
        return result;
    }
    CloseHandle(hFile);
	result.data = hFileContent;
    result.size = dFileSize;
    return result;
}

WORD fileType;
vector<string> names;

const vector<string> explode(const string &s, const char &c) {
    string buff{""};
    vector<string> v;
    for (auto n : s)
    {
        if (n != c)
            buff += n;
        else if (n == c && buff != "")
        {
            v.push_back(buff);
            buff = "";
        }
    }
    if (buff != "")
        v.push_back(buff);
    return v;
}

// Função auxiliar para ler o arquivo binário para um vetor
bool getFileContent(const string &path, vector<unsigned char> &buffer) {
    ifstream file(path, ios::binary | ios::ate);
    if (!file.is_open()) return false;
    streamsize size = file.tellg();
    file.seekg(0, ios::beg);
    buffer.resize(size);
    if (file.read((char*)buffer.data(), size))
        return true;
    return false;
}

bool getImageFileHeaders(string fileName, IMAGE_NT_HEADERS &headers) {
    std::wstring wFileName = std::wstring(fileName.begin(), fileName.end());
    HANDLE fileHandle = CreateFileW(
        wFileName.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        0);
    if (fileHandle == INVALID_HANDLE_VALUE)
        return false;

    HANDLE imageHandle = CreateFileMappingW(
        fileHandle,
        nullptr,
        PAGE_READONLY,
        0,
        0,
        nullptr);
    if (imageHandle == 0)
    {
        CloseHandle(fileHandle);
        return false;
    }
    void *imagePtr = MapViewOfFile(
        imageHandle,
        FILE_MAP_READ,
        0,
        0,
        0);
    if (imagePtr == nullptr)
    {
        CloseHandle(imageHandle);
        CloseHandle(fileHandle);
        return false;
    }
    PIMAGE_NT_HEADERS headersPtr = ImageNtHeader(imagePtr);
    if (headersPtr == nullptr)
    {
        UnmapViewOfFile(imagePtr);
        CloseHandle(imageHandle);
        CloseHandle(fileHandle);
        return false;
    }
    headers = *headersPtr;
    UnmapViewOfFile(imagePtr);
    CloseHandle(imageHandle);
    CloseHandle(fileHandle);
    return true;
}

void listDLLFunctions(string sADllName, vector<string> &slListOfDllFunctions) {
    DWORD *dNameRVAs(0);
    _IMAGE_EXPORT_DIRECTORY *ImageExportDirectory;
    unsigned long cDirSize;
    _LOADED_IMAGE LoadedImage;
    string sName;
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

void generateDEF(string name, vector<string> names) {
    std::fstream file;
    file.open(name + ".def", std::ios::out);
    file << "LIBRARY " << name << std::endl;
    file << "EXPORTS" << std::endl;
    for (int i = 0; i < names.size(); i++)
    {
        file << "\t" << names[i] << "=Fake" << names[i] << " @" << i + 1 << std::endl;
    }
    file.close();
}

bool generateMainCPP(string name, vector<string> names, string originalDllPath, RawFile exe, bool useLogs) {
    // Ler o binário da DLL original
    vector<unsigned char> dllData;
    if (!getFileContent(originalDllPath, dllData)) {
        cout << "[-] Erro ao ler o binario da DLL original para embutir." << std::endl;
        return false;
    }
    cout << "[+] DLL original lida: " << dllData.size() << " bytes." << std::endl;
    std::fstream file;
    file.open(name + ".cpp", std::ios::out);
    file << "#include <windows.h>" << std::endl;
    file << "#include <stdio.h>" << std::endl;
    file << "#include <string>" << std::endl;
    file << "#include <iostream>" << std::endl;
    file << "#include <vector>" << std::endl;
    file << "#include \"MemoryModule.hpp\"" << std::endl;
    file << "#include \"dll_binary.h\"" << std::endl;
    file << "#include \"your_main.h\"" << std::endl;
    file << std::endl;


    //dll_binary.h
    std::fstream dllBinaryFile;
    dllBinaryFile.open("dll_binary.h", std::ios::out);
    dllBinaryFile << "unsigned char originalDllData[" << dllData.size() << "] = {";
    dllBinaryFile << hex << setfill('0'); 
    for (size_t i = 0; i < dllData.size(); ++i) {
        dllBinaryFile << "0x" << setw(2) << (int)dllData[i];
        if (i != dllData.size() - 1) dllBinaryFile << ",";
    }
    dllBinaryFile << dec;
    dllBinaryFile << "};";
    dllBinaryFile.close();


    file << "struct " << name << "_dll { \n"
         << "\tHMEMORYMODULE dll;\n";
    for (int i = 0; i < names.size(); i++)
    {
        file << "\tFARPROC Orignal" << names[i] << ";\n";
    }
    file << "} " << name << ";\n\n";
    // Generate Exports
    if (fileType == IMAGE_FILE_MACHINE_AMD64) {
        file << "extern \"C\"\n{\n";
        file << "void LogToFile(const char* msg);\n"; 
        for (int i = 0; i < names.size(); i++) {
            if (useLogs) {
                file << "\t__attribute__((naked)) void Fake" << names[i] << "() {\n";
                file << "\t\tasm volatile (\n";
                // 1. Salva registradores voláteis (7 regs = 56 bytes)
                file << "\t\t\t\"push %%rax\\n\\t\" \"push %%rcx\\n\\t\" \"push %%rdx\\n\\t\" \"push %%r8\\n\\t\" \"push %%r9\\n\\t\" \"push %%r10\\n\\t\" \"push %%r11\\n\\t\"\n";
                
                // 2. Aloca Shadow Space (32 bytes). 
                // A stack já estava alinhada após os pushes (56 + 8 return addr = 64).
                // Subtrair 32 mantem alinhamento de 16 bytes.
                file << "\t\t\t\"sub $32, %%rsp\\n\\t\"\n"; 
                
                // 3. Prepara argumento e chama
                file << "\t\t\t\"mov %[str], %%rcx\\n\\t\"\n";
                file << "\t\t\t\"call LogToFile\\n\\t\"\n";
                
                // 4. Restaura Stack e Registradores
                file << "\t\t\t\"add $32, %%rsp\\n\\t\"\n";
                file << "\t\t\t\"pop %%r11\\n\\t\" \"pop %%r10\\n\\t\" \"pop %%r9\\n\\t\" \"pop %%r8\\n\\t\" \"pop %%rdx\\n\\t\" \"pop %%rcx\\n\\t\" \"pop %%rax\\n\\t\"\n";
                
                // 5. Pula para original
                file << "\t\t\t\"jmp *%[orig]\"\n";
                file << "\t\t\t: : [str] \"r\" (\"" << names[i] << "\"), [orig] \"m\" (" << name << ".Orignal" << names[i] << ") : \"memory\");\n";
                file << "\t}\n";
            } else {
                file << "\t__attribute__((naked)) void Fake" << names[i] << "() { asm volatile (\"jmp *%0\" : : \"m\" (" << name << ".Orignal" << names[i] << ")); }\n";
            }
        }
        file << "}\n";
    } else {
        for (int i = 0; i < names.size(); i++)
        {
            if (useLogs) {
                file << "__declspec(naked) void Fake" << names[i] << "() {\n";
                file << "\t_asm {\n";
                file << "\t\tpushad\n"; // Salva todos os registradores de propósito geral
                file << "\t}\n";
                file << "\tLogToFile(\"" << name << "\\n\");\n";
                file << "\t_asm {\n";
                file << "\t\tpopad\n"; // Restaura os registradores
                file << "\t\tjmp [" << name << ".Orignal" << names[i] << "]\n";
                file << "\t}\n";
                file << "}\n";
            } else {
                file << "__declspec(naked) void Fake" << names[i] << "() { _asm { jmp[" << name << ".Orignal" << names[i] << "] } }\n";
            }
        }
    }
    file << "\n";


    //exe_binary.h
    if (exe.data != nullptr) {
        std::fstream exeBinaryFile;
        exeBinaryFile.open("exe_binary.h", std::ios::out);
        cout << "Exe lido com sucesso! Tamanho: " << exe.size << " bytes.\n";
        unsigned char* pBuffer = (unsigned char*) exe.data;
        exeBinaryFile << "size_t payloadSize = " << exe.size << ";\n";
        exeBinaryFile << "unsigned char rawData[" << exe.size << "] = {";
        for (DWORD i = 0; i < exe.size; i++) {
            exeBinaryFile << "0x" << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << (int)pBuffer[i];
            if (i < exe.size - 1) {
                exeBinaryFile << ",";
            }
        }
        exeBinaryFile << "};";
        HeapFree(GetProcessHeap(), 0, exe.data);
        exeBinaryFile.close();
    } else {
        printf("Falha ao ler o arquivo.\n");
        return false;
    }


    // DllMain Modificado para carregar da memória
    file << "BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {" << std::endl;
    file << "\tswitch (ul_reason_for_call)" << std::endl;
    file << "\t{" << std::endl;
    file << "\tcase DLL_PROCESS_ATTACH:" << std::endl;
    file << "\t{" << std::endl;
    file << "\t\tYourMain();\n";
    // Carregamento via MemoryModule
    file << "\t\t" << name << ".dll = MemoryModule::MemoryLoadLibrary(originalDllData, sizeof(originalDllData));" << std::endl;
    file << "\t\tif (" << name << ".dll == NULL)" << std::endl;
    file << "\t\t{" << std::endl;
    file << "\t\t\tMessageBox(0, \"Cannot load embedded library from memory\", \"Proxy Error\", MB_ICONERROR);" << std::endl;
    file << "\t\t\tExitProcess(0);" << std::endl;
    file << "\t\t}" << std::endl;
    for (int i = 0; i < names.size(); i++)
    {
        file << "\t\t" << name << ".Orignal" << names[i] << " = MemoryModule::MemoryGetProcAddress(" << name << ".dll, \"" << names[i] << "\");" << std::endl;
    }
    file << "" << std::endl;
    file << "\t\tbreak;" << std::endl;
    file << "\t}" << std::endl;
    file << "\tcase DLL_PROCESS_DETACH:" << std::endl;
    file << "\t{" << std::endl;
    file << "\t\tif (" << name << ".dll) MemoryModule::MemoryFreeLibrary(" << name << ".dll);" << std::endl;
    file << "\t}" << std::endl;
    file << "\tbreak;" << std::endl;
    file << "\t}" << std::endl;
    file << "\tYourEnd();" << std::endl;
    file << "\treturn TRUE;" << std::endl;
    file << "}" << std::endl;
    file.close();
    return true;
}

void generateASM(string name) {
    std::fstream file;
    file.open(name + ".asm", std::ios::out);
    file << ".data" << std::endl;
    file << "extern PA : qword" << std::endl;
    file << ".code" << std::endl;
    file << "RunASM proc" << std::endl;
    file << "jmp qword ptr [PA]" << std::endl;
    file << "RunASM endp" << std::endl;
    file << "end" << std::endl;
    file.close();
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        cout << "Usage: generator.exe <path_to_dll> <path_to_exe>" << std::endl;
        return 1;
    }
    std::vector<std::string> args(argv, argv + argc);
    IMAGE_NT_HEADERS headers;
    if (getImageFileHeaders(args[1], headers))
    {
        fileType = headers.FileHeader.Machine;
    }
    else {
        cout << "Error reading PE headers." << std::endl;
        return 1;
    }
    // Get filename
    vector<std::string> fileNameV = explode(args[1], '\\');
    std::string fileName = fileNameV[fileNameV.size() - 1];
    fileName = fileName.substr(0, fileName.size() - 4);
    // Get dll export names
    listDLLFunctions(args[1], names);
    // Create Def File e CPP com binário embutido
    generateDEF(fileName, names);
    RawFile exe = GetFileContent(args[2].c_str());
    if (!generateMainCPP(fileName, names, args[1], exe, false)) {
        return 1;
    }
    if (fileType == IMAGE_FILE_MACHINE_AMD64) {
        generateASM(fileName);
    }
    cout << "[+] Codigo gerado com sucesso!" << std::endl;
    return 0;
}