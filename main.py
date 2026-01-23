import os
import shutil
import sys

def generate_dll(dll_base_name:str, files_folder:str="") -> None:
    print(f"Compilando nova {dll_base_name}.dll")
    compilation_command = (
        f'g++ -shared -o "{dll_base_name}.dll" "{files_folder}{dll_base_name}.cpp" "{files_folder}{dll_base_name}.def" -s -static-libgcc -static-libstdc++'
    )
    if os.system(compilation_command) != 0:
        print("Erro na compilação final.")
        sys.exit(1)
    if os.path.exists(f"output/{dll_base_name}.dll"):
        os.remove(f"output/{dll_base_name}.dll")
    if os.path.exists(f"{dll_base_name}.dll"):
        shutil.move(f"{dll_base_name}.dll", "output/")

if __name__ == "__main__":

    if sys.argv[1] == "-recompiledll":
        if not os.path.exists("output/"):
            print("Output folder does not exists!")
            sys.exit(1)
        for file in os.listdir("output/"):
            if file.endswith(".cpp"):
                generate_dll(os.path.splitext(os.path.basename(file))[0], "output/")
                break
        sys.exit(1)

    if len(sys.argv) < 2:
        print("Uso: python main.py <caminho_da_dll_original>")
        exit(1)

    original_path = sys.argv[1]
    clean_all = bool(int(sys.argv[2]))
    
    dll_name = os.path.basename(original_path)
    dll_base_name = os.path.splitext(dll_name)[0]

    if os.path.exists("output/"):
        shutil.rmtree("output/")

    if not os.path.exists("output/"):
        os.mkdir("output")

    if not os.path.exists(original_path):
        print(f"Erro: O arquivo '{original_path}' não foi encontrado.")
        exit(1)

    print(f"--- Processando: {dll_name} ---")
    if os.system("g++ main.cpp -o gerador.exe -limagehlp") != 0:
        print("Erro: Falha ao compilar main.cpp.")
        exit(1)

    try:
        shutil.copy(original_path, dll_name) #faz copia da dll
    except shutil.SameFileError:
        pass

    print("Gerando código proxy...")
    if os.system(f'gerador.exe "{dll_name}"') != 0:
        print("Erro: O gerador falhou. Verifique se a DLL é válida.")
        exit(1)
        
    local_path = os.path.abspath(dll_name)
    absolute_input_path = os.path.abspath(original_path)

    if os.path.exists(local_path):
        if local_path != absolute_input_path:
            os.remove(local_path)
        else:
            print("Aviso: O input e o output são o mesmo local. O arquivo original será sobrescrito!")

    generate_dll(dll_base_name)

    temp_files = [
        f"{dll_base_name}.cpp",
        f"{dll_base_name}.asm",
        f"{dll_base_name}.def",
        "gerador.exe"
    ]
    if clean_all:
        print("Limpando temporários...")
        for file in temp_files:
            if os.path.exists(file):
                try:
                    os.remove(file)
                except:
                    pass
    else:
        for file in temp_files:
            try:
                shutil.move(file, "output/")
            except Exception as e:
                pass

    print(f"--- Sucesso! DLL proxy '{dll_name}' foi criada ---")