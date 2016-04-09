;------------------------------------------------------------------
;
;   Enumerate Microsoft Windows Local Security Authority privileges
;   Copyright (C) 2016	  Marcin Cieslak <saper@saper.info>
;
;   This program is free software: you can redistribute it and/or modify
;   it under the terms of the GNU General Public License as published by
;   the Free Software Foundation, either version 3 of the License, or
;   (at your option) any later version.
;
;   This program is distributed in the hope that it will be useful,
;   but WITHOUT ANY WARRANTY; without even the implied warranty of
;   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;   GNU General Public License for more details.
;
;   You should have received a copy of the GNU General Public License
;   along with this program in the COPYING file.  
;   If not, see <http://www.gnu.org/licenses/>.
;
;------------------------------------------------------------------

            SECTION .data
RCKEEP
            dd	0
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

CRLFDATA:
                        db  13, 10

PrivNameBuf:
                        db      'S', 0, 'e', 0
PrivName:
                        resw	40
PrivNameBufEnd:

LsaUnicodeStr:

StrLen:		            dw      0
BufLen:		            dw      PrivNameBufEnd-PrivNameBuf
PrivString:             dd      PrivNameBuf

%macro                  constr     2
%%str:
%1:                     db      %2
%%strend:
%1_Size                 equ     %%strend-%%str
%endmacro

                        constr     Privilege,       'Privilege'
                        constr     Right,           'Right'
                        constr     LsaOpenPolicy,   'LsaOpenPolicy: '
                        constr     LsaClose,        'LsaClose: '
                        constr     LsaEAWUR,        'LsaEnumerateAccountsWithUserRight: '
                        constr     MsgConvSID,      'ConvertSidToStringSid: '

%include 'priv.asm'

                        SECTION    .bss
STDOUT                  resd       1


                        SECTION    .code
;
START:
                        push    -11D            ;STD_OUTPUT_HANDLE
                        call    GetStdHandle
                        mov     [STDOUT], eax

                        push    LSAHANDLE
                        push    0x801
                        push    LSAOBJ
                        push    0
        	            call	LsaOpenPolicy

                        test	eax, eax
                        mov     ecx, MsgLsaOpenPolicy_Size
                        mov     esi, MsgLsaOpenPolicy
                        jnz     FAIL

	                    sub     ecx, ecx		; privilege #
                        
LOOP:
	                    mov     esi, PrivTable
                        lea     eax, [esi + ecx * 4]
                        cmp     w[eax], 0
                        jz      FINISH

D2sHEXb:                	                     ;eax=value (allow for reverse storage) [edi]=string
                        add     edi, 7h          ;point to end of string and translate
                    	mov     ecx, 8h          ;the eight characters right to left

L100:
                        mov     ebx, eax
                        shr     eax, 4h
                        and     ebx, 0Fh
                        mov     dl,  [sHEXb+ebx]
                        mov     [edi], dl
                        dec     edi
                        loop    L100
                        ret

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
