;------------------------------------------------------------------
;
;      HelloWorld1 - copyright Jeremy Gordon 2002
;
;      SIMPLE "HELLO WORLD" WINDOWS CONSOLE PROGRAM - for GoAsm
;
;      Assemble using GoAsm HelloWorld1 (produces PE COFF file)
;      Then link as windows console program using GoLink as follows:-
;      GoLink /console helloworld1.obj kernel32.dll
;      (add -debug coff if you want to watch the program in the debugger)
;
;      Note that the GetStdHandle and WriteFile calls are to kernel32.dll
;------------------------------------------------------------------
;
DATA SECTION
;
;
RCKEEP DD 0             ;temporary place to keep things
LSAOBJ	
	DD	0
	DD	0
	DD	0
	DD	0
	DD	0
LSAHANDLE
	DD	0
sHEXb
	DB "0123456789ABCDEF"
RESULTSTR
	DB '00000000',13,10
ENUMCOUNT
	DD  0
ENUMBUF
	DD  0
STDOUT
	DD  0

LsaUnicodeStr STRUCT
	StrLen		DW
	BufLen		DW
	PrivString	DD
ENDS

#include priv.a
#include privlist.a

MsgLsaOpenPolicy:
	DB 'LsaOpenPolicy: '
MsgLsaClose:
	DB 'LsaClose: '
MsgLsaEAWUR:
	DB 'LsaEnumerateAccountsWithUserRight: '
;
CODE SECTION
;
START:
invoke  GetStdHandle, -11D ;STD_OUTPUT_HANDLE
mov	[STDOUT],eax
invoke	LsaOpenPolicy, 0, addr LSAOBJ, 0x801, addr LSAHANDLE
test	eax, eax
mov     ecx,sizeof MsgLsaOpenPolicy
mov	esi,addr MsgLsaOpenPolicy
jnz	>FAIL

mov	esi, addr PRIVILEGES
mov	ecx, 0
lea	eax, [esi + ecx * 8]
invoke  LsaEnumerateAccountsWithUserRight, [LSAHANDLE], eax, addr ENUMBUF, addr ENUMCOUNT
STOP:
test	eax,eax
mov	ecx,sizeof MsgLsaEAWUR
mov	esi,addr MsgLsaEAWUR
jnz	>FAIL

invoke  LsaClose, [LSAHANDLE]
test	eax,eax
mov	ecx,sizeof MsgLsaClose
mov	esi,addr MsgLsaClose
jnz	>FAIL
ret

FAIL:
push	eax
invoke  WriteFile, [STDOUT], esi, ecx, addr RCKEEP, 0
pop	eax
mov	edi,addr RESULTSTR
call	D2sHEXb

invoke  GetStdHandle, -11D ;STD_OUTPUT_HANDLE
invoke  WriteFile, eax, addr RESULTSTR, 10D, addr RCKEEP, 0
xor	eax,eax
ret

D2sHEXb:                ;eax=value (allow for reverse storage) [edi]=string
add     edi,7h          ;point to end of string and translate
mov     ecx,8h          ;the eight characters right to left
;
L100:
mov     ebx,eax
shr     eax,4h
and     ebx,0Fh
mov     dl,[sHEXb+ebx]
mov     [edi],dl
dec     edi
loop    L100
ret
