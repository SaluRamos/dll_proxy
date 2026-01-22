import os
import shutil
import sys

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python main.py <caminho_da_dll_original>")
        exit(1)

    original_path = sys.argv[1]
    clean_all = True if sys.argv[2] == "True" else False
    
    dll_name = os.path.basename(original_path)
    dll_base_name = os.path.splitext(dll_name)[0]

    if not os.path.exists(original_path):
        print(f"Erro: O arquivo '{original_path}' não foi encontrado.")
        exit(1)

    print(f"--- Processando: {dll_name} ---")
    if os.system("g++ main.cpp -o gerador.exe -limagehlp") != 0:
        print("Erro: Falha ao compilar main.cpp.")
        exit(1)

    try:
        shutil.copy(original_path, dll_name)
    except shutil.SameFileError:
        pass

    print("Gerando código proxy...")
    if os.system(f'gerador.exe "{dll_name}"') != 0:
        print("Erro: O gerador falhou. Verifique se a DLL é válida.")
        if os.path.exists("gerador.exe"): os.remove("gerador.exe")
        exit(1)

    local_path = os.path.abspath(dll_name)
    absolute_input_path = os.path.abspath(original_path)

    if os.path.exists(local_path):
        if local_path != absolute_input_path:
            os.remove(local_path)
        else:
            print("Aviso: O input e o output são o mesmo local. O arquivo original será sobrescrito!")

    print(f"Compilando nova {dll_name}...")
    compilation_command = (
        f"g++ -shared -o \"{dll_name}\" \"{dll_base_name}.cpp\" \"{dll_base_name}.def\" "
        "-s -static-libgcc -static-libstdc++"
    )
    
    if os.system(compilation_command) != 0:
        print("Erro na compilação final.")

    if clean_all:
        temp_files = [
            f"{dll_base_name}.cpp",
            f"{dll_base_name}.asm",
            f"{dll_base_name}.def",
            "gerador.exe"
        ]
        print("Limpando temporários...")
        for file in temp_files:
            if os.path.exists(file):
                try:
                    os.remove(file)
                except:
                    pass

    print(f"--- Sucesso! A nova DLL '{dll_name}' foi criada nesta pasta. ---")