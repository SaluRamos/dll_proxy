Creates a new DLL that incorporates the original DLL, acting as a proxy.

# How to run
  
run ```python main.py```  
  
FLAGS:
```-projectname``` used to place all generated stuff inside a folder with this name  
```-dllpath``` path to the target dll  
```-exepath``` exe to embed  
  
Example:  
  
```python main.py -projectname=example_name -dllpath=dlls/D3D11 -exepath=exes/calc``` (does not requires '.dll' at the end)  
  
after modifying the generated code inside 'example_name' folder project, run to recompile:  
  
```python main.py -projectname=example_name -recompile```  

# Relevant files

main.py -> builds a project folder for a target DLL
main.cpp -> generates the proxy DLL with same export address table.
utils/MemoryModule -> load a dll from a array, GetAddress from function
your_main.h -> custom dll proxy code

# How it works

Get all function from export address table of the target dll.
Save the dll binary as a unsigned char array.
Constructs a .cpp file that uses MemoryModule to load the binary array in to memory.
This .cpp file uses a DLL template that exports the same functions of the target dll.
these functions uses assembly code that jumps to memory loaded target dll.
The functionality is the same, but we can add any code to it.
