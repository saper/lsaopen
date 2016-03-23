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

mov	ecx, 0

LOOP:
mov	esi, addr PRIVILEGES
lea	eax, [esi + ecx * 8]
cmp	w[eax], 0
jz	>FINISH

push	eax
mov     eax, ecx
push    ecx
mov	edi,addr RESULTSTR
call	D2sHEXb
invoke  WriteFile, [STDOUT], addr RESULTSTR, 10D, addr RCKEEP, 0
pop     ecx
pop	eax

push 	ecx
invoke  LsaEnumerateAccountsWithUserRight, [LSAHANDLE], eax, addr ENUMBUF, addr ENUMCOUNT
pop	ecx

STOP:
cmp	eax, 0x8000001A		; STATUS_NO_MORE_ENTRIES
jz	>SOFTFAIL
cmp	eax, 0xC0000060		; STATUS_NO_SUCH_PRIVILEGE
jz	>SOFTFAIL

test	eax,eax
jnz	>PRIVFAIL

OUTPUTSIDS:

NEXT:
inc	ecx
jmp	LOOP

SOFTFAIL:
push	ecx
push	eax
invoke  WriteFile, [STDOUT], 'E', 1, addr RCKEEP, 0
pop	eax
mov	edi,addr RESULTSTR
call	D2sHEXb
invoke  WriteFile, [STDOUT], addr RESULTSTR, 10D, addr RCKEEP, 0
pop	ecx
inc	ecx
jmp	LOOP

FINISH:
invoke  LsaClose, [LSAHANDLE]

test	eax,eax
mov	ecx,sizeof MsgLsaClose
mov	esi,addr MsgLsaClose
jnz	>FAIL

xor	eax, eax
ret

PRIVFAIL:
mov	ecx,sizeof MsgLsaEAWUR
mov	esi,addr MsgLsaEAWUR

FAIL:
push	eax
invoke  WriteFile, [STDOUT], esi, ecx, addr RCKEEP, 0
pop	eax
mov	edi,addr RESULTSTR
call	D2sHEXb
invoke  WriteFile, [STDOUT], addr RESULTSTR, 10D, addr RCKEEP, 0
xor	eax,eax
inc	eax
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
