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
	DB '00000000'
ENUMCOUNT
	DD  0
ENUMBUF
	DD  0
SIDSTR
	DD  0

CRLFDATA
	DB  13, 10

STDOUT
	DD  0

LsaUnicodeStr STRUCT
	StrLen		DW
	BufLen		DW
	PrivString	DD
ENDS

#include priv.a
#include privlist.a

PrivNameBuf	DB	40 DUP 0
PrivNameBufEnd

MsgLsaOpenPolicy:
	DB 'LsaOpenPolicy: '
MsgLsaClose:
	DB 'LsaClose: '
MsgLsaEAWUR:
	DB 'LsaEnumerateAccountsWithUserRight: '
MsgConvSID:
	DB 'ConvertSidToStringSid: '
;
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

push 	ecx
invoke  LsaEnumerateAccountsWithUserRight, [LSAHANDLE], eax, addr ENUMBUF, addr ENUMCOUNT
pop	ecx

cmp	eax, 0x8000001A		; STATUS_NO_MORE_ENTRIES
jz	>SKIP
cmp	eax, 0xC0000060		; STATUS_NO_SUCH_PRIVILEGE
jz	>SKIP
test	eax,eax
jnz	>PRIVFAIL

PRINTNAME:
call	privname
push	ecx
invoke  WriteFile, [STDOUT], addr PrivNameBuf, sizeof PrivNameBuf, addr RCKEEP, 0

STOP:
OUTPUTSIDS:
mov	ecx,0
cmp	ecx,[ENUMCOUNT]
jz	>NEXT
SIDLOOP:
mov	esi,[ENUMBUF]
push	ecx
invoke	ConvertSidToStringSidA, [esi+ecx*4],addr SIDSTR
test	eax,eax
jz	>BADSID
mov	edi,[SIDSTR]
sub	ecx,ecx
not	ecx
sub	eax,eax
cld
repne   scasb
not	ecx
dec	ecx
invoke  WriteFile, [STDOUT], [SIDSTR], ecx, addr RCKEEP, 0
pop	ecx
inc	ecx
cmp	ecx,[ENUMCOUNT]
jb	SIDLOOP

NEXT:
pop	ecx ; privilege #
call	CRLF
SKIP:
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

BADSID:
pop	ecx
pop	ecx
invoke	GetLastError
mov	ecx,sizeof MsgConvSID
mov	esi,addr MsgConvSID
jmp	FAIL

PRIVFAIL:
mov	ecx,sizeof MsgLsaEAWUR
mov	esi,addr MsgLsaEAWUR

FAIL:
push	eax
invoke  WriteFile, [STDOUT], esi, ecx, addr RCKEEP, 0
pop	eax
mov	edi,addr RESULTSTR
call	D2sHEXb
invoke  WriteFile, [STDOUT], addr RESULTSTR, sizeof RESULTSTR, addr RCKEEP, 0
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

privname:
mov	edi, addr PrivNameBuf
mov	esi, addr PRIVILEGES
xor	edx, edx
mov	dx,  w[esi+ecx*8]
mov	esi, d[esi+ecx*8+4]
L101:
movsb
inc	esi
dec	dx
dec	dx
jnz	L101

; Pad privilege name with spaces
mov	al, 0x20
L102:
cmp	edi, addr PrivNameBufEnd
jge	>L103
stosb
jmp	L102

L103:
ret

CRLF:
push	ecx
invoke  WriteFile, [STDOUT], addr CRLFDATA, 2, addr RCKEEP, 0
pop	ecx
ret
