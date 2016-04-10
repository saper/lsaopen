nasm -f win32 lsaopen.asm
c:\sw\asm\golink /console /debug=coff lsaopen.obj kernel32.dll advapi32.dll
