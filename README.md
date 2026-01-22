compilar gerador:

```g++ main.cpp -o gerador.exe -limagehlp```

gerar código:

```./gerador.exe steam_api64.dll```

gerar dll proxy:

```g++ -shared -o steam_api64.dll steam_api64.cpp steam_api64.def -s -static-libgcc -static-libstdc++```