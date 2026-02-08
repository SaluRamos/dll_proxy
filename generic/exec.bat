cls

g++ -I../utils generic_dll.cpp -shared -s -static-libgcc -static-libstdc++ -o main.dll -limagehlp

g++ -I../utils test_generic.cpp -o main.exe

main.exe