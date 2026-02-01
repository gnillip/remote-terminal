pip install pyinstaller
pyinstaller --onefile --uac-admin .\server.pyw

del server.spec
rmdir /s /q build

copy .\dist\server.exe .\server.exe
rmdir /s /q dist