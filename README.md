### DLL Proxy
  
Creates a new DLL which sits between a program and the original DLL to intercept calls.  
The real DLL is embedded in the proxy.  
Based on [ProxiFy](https://www.codeproject.com/Articles/1179147/ProxiFy-Automatic-Proxy-DLL-Generation)  
  
### Requirements
  
- MinGW  
  
### How to run
  
run ```python main.py```  
  
FLAGS:
```-projectname``` used to place all generated stuff inside a folder with this name  
```-dllpath``` path to the target dll  
```-recompile``` recompile project dll  
  
Example:  
  
```python main.py -projectname=example_name -dllpath=dlls/D3D11``` (does not requires '.dll' at the end)  
  
after editing generated code inside 'example_name' project, run:  
  
```python main.py -projectname=example_name -recompile```  