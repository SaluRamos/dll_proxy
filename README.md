### DLL Proxy
  
Creates a new DLL which sits between a program and the original DLL to intercept calls.  
Based on [ProxiFy](https://www.codeproject.com/Articles/1179147/ProxiFy-Automatic-Proxy-DLL-Generation)  
  
### Requirements
  
- MinGW  
  
### How to run
  
first arg is dll path.  
second arg is '1' to delete temp files or '0' to not delete temp files.  
  
```python main.py ./dlls/steam_api64.dll 1```  
  
Notice: The real DLL must be in System32 to be found by the proxy DLL
