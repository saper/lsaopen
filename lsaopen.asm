;------------------------------------------------------------------
;
;------------------------------------------------------------------
;
DATA SECTION
;
;
RCKEEP	dd 0             ;temporary place to keep things
LSAOBJ	
	dd	0
	dd	0
	dd	0
	dd	0
	dd	0
LSAHANDLE
	dd	0
sHEXb
	db "0123456789ABCDEF"
RESULTSTR
	db '00000000'
ENUMCOUNT
	dd  0
ENUMBUF
	dd  0
SIDSTR
	dd  0

CRLFDATA
	db  13, 10

STDOUT
	dd  0

LsaUnicodeStr STRUCT
	StrLen		dw
	BufLen		dw
	PrivString	dd
ENDS

#include priv.a
#include privlist.a

PrivNameBuf
	db	40 DUP 0
PrivNameBufEnd

MsgLsaOpenPolicy:
	db 'LsaOpenPolicy: '
MsgLsaClose:
	db 'LsaClose: '
MsgLsaEAWUR:
	db 'LsaEnumerateAccountsWithUserRight: '
MsgConvSID:
	db 'ConvertSidToStringSid: '
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

	sub	ecx, ecx		; privilege #
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

	sub	edx,edx                 ; SID #
OUTPUTSIDS:

	push	edx
	call	privname
	pop	edx
	push	ecx
	push    edx
	invoke  WriteFile, [STDOUT], addr PrivNameBuf, sizeof PrivNameBuf, addr RCKEEP, 0
	pop	edx

	cmp	edx,[ENUMCOUNT]
	jz	>NEXT
SIDLOOP:
	mov	esi,[ENUMBUF]
	push	edx
	invoke	ConvertSidToStringSidA, [esi+edx*4],addr SIDSTR
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
	call	CRLF
	pop	edx
	inc	edx
	pop	ecx
	cmp	edx,[ENUMCOUNT]
	jb	OUTPUTSIDS
	inc	ecx
	jmp	LOOP

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

D2sHEXb:                	;eax=value (allow for reverse storage) [edi]=string
	add     edi,7h          ;point to end of string and translate
	mov     ecx,8h          ;the eight characters right to left

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
