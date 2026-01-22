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

using namespace std;

// Check if its 32bit or 64bit
WORD fileType;

// Exported names
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
	DWORD *dNameRVAs2(0);
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

	// Loop them
	for (int i = 0; i < names.size(); i++)
	{
		file << "\t" << names[i] << "=Fake" << names[i] << " @" << i + 1 << endl;
	}

	file.close();
}

void generateMainCPP(string name, vector<string> names)
{
	size_t fileNameLength = name.size() + 6;
	std::fstream file;
	file.open(name + ".cpp", std::ios::out);
	file << "#include <windows.h>" << endl
		<< "#include <stdio.h>" << endl
		<< endl;

	file << "struct " << name << "_dll { \n"
		 << "\tHMODULE dll;\n";

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
			// __attribute__((naked)) diz ao GCC para não criar prólogo/epílogo de função
			// asm volatile faz o jump. 
			// "jmp *%0" é sintaxe AT&T para jump indireto
			// "m" (...) passa o endereço da variável da struct como operando de memória
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

	file << "BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {" << endl;

	file << "\tchar path[MAX_PATH];" << std::endl;
	file << "\tswitch (ul_reason_for_call)" << std::endl;
	file << "\t{" << std::endl;
	file << "\tcase DLL_PROCESS_ATTACH:" << std::endl;
	file << "\t{" << std::endl;

	// --- NOVO CÓDIGO DE LOG AQUI ---
	file << "\t\t// Log simples para verificar carregamento" << std::endl;
    file << "\t\tFILE* fLog = fopen(\"proxy_log.txt\", \"a\");" << std::endl;
    file << "\t\tif (fLog) {" << std::endl;
    file << "\t\t\tfprintf(fLog, \"[" << name << ".dll] Carregada com sucesso! Handle: %p\\n\", hModule);" << std::endl;
    file << "\t\t\tfclose(fLog);" << std::endl;
    file << "\t\t}" << std::endl;
	// -------------------------------

	file << "\t\tCopyMemory(path + GetSystemDirectory(path, MAX_PATH - " << fileNameLength << "), \"\\\\" << name << ".dll\", " << fileNameLength + 1 << ");" << std::endl;
	file << "\t\t" << name << ".dll = LoadLibrary(path);" << std::endl;
	file << "\t\tif (" << name << ".dll == NULL)" << std::endl;
	file << "\t\t{" << std::endl;
	file << "\t\t\tMessageBox(0, \"Cannot load original " << name << ".dll library\", \"Proxy\", MB_ICONERROR);" << std::endl;
	file << "\t\t\tExitProcess(0);" << std::endl;
	file << "\t\t}" << std::endl;

	for (int i = 0; i < names.size(); i++)
	{
		file << "\t\t" << name << ".Orignal" << names[i] << " = GetProcAddress(" << name << ".dll, \"" << names[i] << "\");" << std::endl;
	}

	file << "" << std::endl;
	file << "\t\tbreak;" << std::endl;
	file << "\t}" << std::endl;
	file << "\tcase DLL_PROCESS_DETACH:" << std::endl;
	file << "\t{" << std::endl;
	file << "\t\tFreeLibrary(" << name << ".dll);" << std::endl;
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
	std::vector<std::string> args(argv, argv + argc);

	IMAGE_NT_HEADERS headers;
	if (getImageFileHeaders(args[1], headers))
	{
		fileType = headers.FileHeader.Machine;
	}

	// Get filename
	vector<std::string> fileNameV = explode(args[1], '\\');
	std::string fileName = fileNameV[fileNameV.size() - 1];
	fileName = fileName.substr(0, fileName.size() - 4);

	// Get dll export names
	listDLLFunctions(args[1], names);

	// Create Def File
	generateDEF(fileName, names);
	generateMainCPP(fileName, names);

	if (fileType == IMAGE_FILE_MACHINE_AMD64)
		generateASM(fileName);

	return 0;
}