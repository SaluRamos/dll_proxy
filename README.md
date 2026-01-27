### DLL Proxy
  
Creates a new DLL that incorporates the original DLL, acting as a proxy.  
Based on [ProxiFy](https://www.codeproject.com/Articles/1179147/ProxiFy-Automatic-Proxy-DLL-Generation)  
  
### Requirements
  
- MinGW  
- Python  
  
### How to run
  
run ```python main.py```  
  
FLAGS:
```-projectname``` used to place all generated stuff inside a folder with this name  
```-dllpath``` path to the target dll  
```-exepath``` exe to embed  
```-recompile``` recompile project dll  
  
Example:  
  
```python main.py -projectname=example_name -dllpath=dlls/D3D11 -exepath=exes/calc``` (does not requires '.dll' at the end)  
  
after modifying the generated code inside 'example_name' folder project, run to recompile:  
  
```python main.py -projectname=example_name -recompile```  
