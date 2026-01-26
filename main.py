import os
import shutil
import sys

project_name = ""
recompile_dll = False
dll_path = ""
exe_path = ""

def recompile_dll_func() -> None:
    if not os.path.exists(f"{project_name}/"):
        print(f"Project {project_name} does not exists!")
        sys.exit(1)
    for file in os.listdir(f"{project_name}/"):
        if file.endswith(".cpp"):
            generate_dll(os.path.splitext(os.path.basename(file))[0], f"{project_name}/")
            break
    sys.exit(1)

def generate_dll(dll_base_name:str, files_folder:str="") -> None:
    print(f"Compilando nova {dll_base_name}.dll")
    compilation_command = (
        f'g++ -shared -o "{dll_base_name}.dll" "{files_folder}{dll_base_name}.cpp" "{files_folder}MemoryModule.c" "{files_folder}{dll_base_name}.def" -s -static-libgcc -static-libstdc++'
    )
    if os.system(compilation_command) != 0:
        print("Erro na compilação final.")
        sys.exit(1)
    if os.path.exists(f"{project_name}/{dll_base_name}.dll"):
        os.remove(f"{project_name}/{dll_base_name}.dll")
    if os.path.exists(f"{dll_base_name}.dll"):
        shutil.move(f"{dll_base_name}.dll", f"{project_name}/")

if __name__ == "__main__":

    for arg in sys.argv[1:]:
        if "-recompile" in arg:
            recompile_dll = True
        if "-projectname" in arg:
            project_name = arg.split("=")[1]
        if "-dllpath" in arg:
            dll_path = arg.split("=")[1] + ".dll"
        if "-exepath" in arg:
            exe_path = arg.split("=")[1] + ".exe"

    if project_name == "":
        print("No project name in flags!")
        sys.exit(1)

    if recompile_dll:
        recompile_dll_func()
    
    if not os.path.exists(dll_path):
        print(f"Erro: O arquivo '{dll_path}' não foi encontrado.")
        sys.exit(1)
    dll_name = os.path.basename(dll_path)
    dll_base_name = os.path.splitext(dll_name)[0]

    if os.path.exists(f"{project_name}/"):
        shutil.rmtree(f"{project_name}/")
    if not os.path.exists(f"{project_name}/"):
        os.mkdir(project_name)

    print(f"--- Processing: {dll_name} ---")
    if os.system("g++ main.cpp -o generator.exe -limagehlp") != 0:
        print("Erro: Falha ao compilar main.cpp.")
        sys.exit(1)

    try:
        shutil.copy(dll_path, dll_name) #faz copia da dll
    except shutil.SameFileError:
        pass

    print("Gerando código proxy...")
    if os.system(f'generator.exe "{dll_name}" "{exe_path}"') != 0:
        print("Erro: O generator falhou. Verifique se a DLL é válida.")
        exit(1)
        
    local_path = os.path.abspath(dll_name)
    absolute_input_path = os.path.abspath(dll_path)

    if os.path.exists(local_path):
        if local_path != absolute_input_path:
            os.remove(local_path)
        else:
            print("Erro: O input e o output são o mesmo local.")
            sys.exit(1)

    try:
        shutil.copy("MemoryModule.c", f"{project_name}/")
        shutil.copy("MemoryModule.h", f"{project_name}/")
        shutil.copy("process_hollowing.h", f"{project_name}/")
    except Exception as e:
        print(f"Aviso: Não foi possível copiar os arquivos do MemoryModule: {e}")

    generate_dll(dll_base_name)

    temp_files = [
        f"{dll_base_name}.cpp",
        f"{dll_base_name}.asm",
        f"{dll_base_name}.def",
        "generator.exe"
    ]
    for file in temp_files:
        try:
            shutil.move(file, f"{project_name}/")
        except Exception as e:
            pass

    print(f"--- Sucesso! DLL proxy '{dll_name}' foi criada ---")