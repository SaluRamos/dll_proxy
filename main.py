import os
import shutil
import sys

if __name__ == "__main__":
    # 1. Validação do Argumento
    if len(sys.argv) < 2:
        print("Uso: python main.py <caminho_da_dll_original>")
        print("Exemplo: python main.py C:/Jogos/Bin/steam_api64.dll")
        exit(1)

    caminho_original = sys.argv[1]
    
    # Extrai apenas o nome do arquivo (ex: "steam_api64.dll") do caminho completo
    nome_dll = os.path.basename(caminho_original)
    # Extrai o nome sem extensão (ex: "steam_api64") para os arquivos .cpp e .def
    nome_base = os.path.splitext(nome_dll)[0]

    # Verifica se o arquivo passado existe
    if not os.path.exists(caminho_original):
        print(f"Erro: O arquivo '{caminho_original}' não foi encontrado.")
        exit(1)

    print(f"--- Processando: {nome_dll} ---")

    # 2. Compilar o gerador (main.cpp)
    # Assume que main.cpp está na mesma pasta deste script python
    if os.system("g++ main.cpp -o gerador.exe -limagehlp") != 0:
        print("Erro: Falha ao compilar main.cpp.")
        exit(1)

    # 3. Trazer a DLL original para a pasta local
    # O gerador precisa ler a DLL. Copiamos para a raiz do script para facilitar.
    # Usamos try/except para o caso de você rodar o script já na pasta onde está a DLL.
    try:
        shutil.copy(caminho_original, nome_dll)
    except shutil.SameFileError:
        pass # O arquivo já está aqui, segue o jogo

    # 4. Executar o gerador
    print("Gerando código proxy...")
    # Usamos aspas f'"{nome_dll}"' para garantir que funcione mesmo se houver espaços
    if os.system(f'gerador.exe "{nome_dll}"') != 0:
        print("Erro: O gerador falhou. Verifique se a DLL é válida.")
        # Limpeza de segurança
        if os.path.exists("gerador.exe"): os.remove("gerador.exe")
        exit(1)

    # 5. Deletar a cópia da DLL original (Input)
    # Precisamos liberar o nome "steam_api64.dll" para que o compilador possa criar a nova (Output)
    # MAS, só deletamos se o arquivo original estiver em outra pasta, para não apagar sua DLL de backup.
    caminho_local = os.path.abspath(nome_dll)
    caminho_input_abs = os.path.abspath(caminho_original)

    if os.path.exists(caminho_local):
        # Se estamos trabalhando numa cópia, deletamos a cópia
        if caminho_local != caminho_input_abs:
            os.remove(caminho_local)
        else:
            print("Aviso: O input e o output são o mesmo local. O arquivo original será sobrescrito!")
            # Em cenários reais de proxy, geralmente queremos sobrescrever ou renomear a original para .old
            # Aqui vou apenas deixar o compilador sobrescrever.

    # 6. Compilar a nova DLL (Proxy)
    print(f"Compilando nova {nome_dll}...")
    
    # Monta o comando dinamicamente usando o nome da DLL
    comando_compilacao = (
        f"g++ -shared -o \"{nome_dll}\" \"{nome_base}.cpp\" \"{nome_base}.def\" "
        "-s -static-libgcc -static-libstdc++"
    )
    
    if os.system(comando_compilacao) != 0:
        print("Erro na compilação final.")
        exit(1)

    # 7. Limpeza dos arquivos temporários gerados
    arquivos_temp = [
        f"{nome_base}.cpp",
        f"{nome_base}.asm",
        f"{nome_base}.def",
        "gerador.exe"
    ]

    print("Limpando temporários...")
    for arq in arquivos_temp:
        if os.path.exists(arq):
            try:
                os.remove(arq)
            except:
                pass

    print(f"--- Sucesso! A nova DLL '{nome_dll}' foi criada nesta pasta. ---")