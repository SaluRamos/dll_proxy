import os
import shutil
import sys
import subprocess

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
            generate_dll(os.path.splitext(os.path.basename(file))[0])
            break
    sys.exit(1)

def generate_dll(dll_base_name:str) -> None:
    print(f"Compilando nova {dll_base_name}.dll")
    command = [
        "g++", "-shared", "-o", f"{project_name}/{dll_base_name}.dll",
        f"{project_name}/{dll_base_name}.cpp", f"{project_name}/MemoryModule.c",
        f"{project_name}/{dll_base_name}.def", "-s", "-static-libgcc", "-static-libstdc++"
    ]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        print("Erro na compilação final.")
        sys.exit(1)

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
    if dll_path == "":
        print("No dll path in flags!")
        sys.exit(1)
    if exe_path == "":
        print("No exe path in flags!")
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
        shutil.copy("utils/MemoryModule.c", f"{project_name}/")
        shutil.copy("utils/MemoryModule.h", f"{project_name}/")
        shutil.copy("utils/process_hollowing.h", f"{project_name}/")
    except Exception as e:
        print(f"erro ao copiar utils: {e}")

    project_files = [
        f"{dll_base_name}.cpp",
        f"{dll_base_name}.asm",
        f"{dll_base_name}.def",
        f"dll_binary.h",
        f"exe_binary.h",
        "generator.exe"
    ]
    for file in project_files:
        try:
            shutil.move(file, f"{project_name}/")
        except Exception as e:
            pass

    generate_dll(dll_base_name)
    print(f"--- Sucesso! DLL proxy '{dll_name}' foi criada ---")