### DLL Proxy
  
Creates a new DLL which sits between a program and the original DLL to intercept calls.  
Based on [ProxiFy](https://www.codeproject.com/Articles/1179147/ProxiFy-Automatic-Proxy-DLL-Generation)  
  
### Requirements
  
- MinGW  
  
### How to run
  
first arg is dll path.  
second arg is 'True' to delete temp files or anything else to not delete temp files.  
  
```python main.py ./dlls/steam_api64.dll True```
