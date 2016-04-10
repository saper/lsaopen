nasm -f win32 lsaopen.asm
c:\sw\asm\golink /console /debug=coff lsaopen.obj kernel32.dll advapi32.dll
# c:\sw\asm\golink /console lsaopen.obj kernel32.dll advapi32.dll
# c:\windbg\ntsd.exe lsaopen.exe

