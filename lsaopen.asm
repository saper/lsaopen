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

extern      GetStdHandle
extern      WriteFile
extern      LsaOpenPolicy
extern      LsaClose
extern      LsaEnumerateAccountsWithUserRight

            SECTION .data

sHEXb:                  db      "0123456789ABCDEF"
CRLFDATA:               db      13, 10
SE:                     db      "Se"
LSAHANDLE:              dd      -1

LsaUnicodeStr:
StrLen:                 dw      0
BufLen:                 dw      PrivNameBufEnd-PrivNameBuf
PrivString:             dd      PrivNameBuf

PrivNameBuf:            db      'S', 0, 'e', 0
PrivName:               times   80 db 0
PrivNameBufEnd: 

SuffixPtr               dd      Privilege
SuffixLen               dd      Privilege_Size

%macro                  constr     2
%%str:
%1:                     db      %2
%%strend:
%1_Size                 equ     %%strend-%%str
%endmacro

                        constr  Privilege,        'Privilege'
                        constr  Right,            'Right'
                        constr  MsgLsaOpenPolicy, 'LsaOpenPolicy: '
                        constr  MsgLsaClose,      'LsaClose: '
                        constr  MsgLsaEAWUR,      'LsaEnumerateAccountsWithUserRight: '
                        constr  MsgConvSID,       'ConvertSidToStringSid: '

%include 'priv.asm'

                        SECTION    .bss
stdout                  resd    1
HexStr                  resb    8

RCKeep                  resd    1
LSAOBJ                  resd    5
ENUMCOUNT               resd    1
ENUMBUF                 resd    1
SIDSTR                  resd    1

%macro                  Write   2
                        push    dword 0
                        push    RCKeep
                        push    %2
                        push    %1
                        push    dword [stdout]
                        call    [WriteFile]
%endmacro

%macro                  Fail?   2
                        test    eax, eax
                        mov     esi, %1
                        mov     ecx, %1_Size
                        jnz     Fail%2
%endmacro


                        SECTION    .code    use32

start:
                        push    -11D            ;STD_OUTPUT_HANDLE
                        call    [GetStdHandle]
                        mov     [stdout], eax

                        push    LSAHANDLE
                        push    dword 0x801
                        push    LSAOBJ
                        push    dword 0
                        call    [LsaOpenPolicy]

                        test    eax, eax
                        Fail?   MsgLsaOpenPolicy, 0

                        mov     esi, PrivTable
PRIVLOOP:
                        mov     eax, [esi]
                        test    eax, eax
                        jz      NextTab

                        push    esi             ; ( -- PrivTableEntry )
                        xor     ecx, ecx
                        mov     esi, eax
                        mov     cl,  [esi]
                        mov     edi, PrivName
                        inc     esi
utf16:                  movsb
                        inc     edi
                        dec     ecx
                        jnz     utf16
                        mov     esi, [SuffixPtr]
                        mov     ecx, [SuffixLen]
utf16p:                 movsb
                        inc     edi
                        dec     ecx
                        jnz     utf16p
                        sub     edi, PrivNameBuf
                        mov     [StrLen], di
            
                        push    ENUMCOUNT
                        push    ENUMBUF
                        push    LsaUnicodeStr
                        push    dword [LSAHANDLE]
                        call    [LsaEnumerateAccountsWithUserRight]

                        cmp     eax, 0x8000001A		; STATUS_NO_MORE_ENTRIES
                        jz      Skip
                        cmp     eax, 0xC0000060		; STATUS_NO_SUCH_PRIVILEGE
                        jz      Skip
                        Fail?   MsgLsaEAWUR, 1

                        Write   SE, 2
                        pop     esi
                        push    esi
                        mov     esi, [esi]
                        xor     ecx, ecx
                        mov     cl, [esi]
                        inc     esi
                        Write   esi, ecx
                        Write   dword [SuffixPtr], dword [SuffixLen]
                        call    CRLF
Skip:                   pop     esi
Next:                   inc     esi
                        inc     esi
                        inc     esi
                        inc     esi
                        jmp     PRIVLOOP
NextTab:
                        cmp     esi, PrivTabEnd
                        jz      Finish
                        mov     eax, Right
                        mov     ebx, Right_Size
                        mov     [SuffixPtr], eax
                        mov     [SuffixLen], ebx
                        jmp     Next
                        
Finish:
                        xor     eax, eax
                        jmp     DoClose

Fail2:                  
                        pop     edx
Fail1:                  
                        pop     edx
Fail0:
                        push    ecx
                        call    ToHex
                        pop     ecx
                        Write   esi, ecx
                        Write   HexStr, 8
                        call    CRLF

                        xor     eax, eax
                        inc     eax

DoClose:
                        push    eax     ; exit code
                        xor     ebx, ebx
                        dec     ebx
                        mov     eax, [LSAHANDLE]
                        cmp     eax, ebx
                        mov     [LSAHANDLE], ebx
                        jz      DoCloseExit
                        push    eax
                        call    [LsaClose]
                        Fail?   MsgLsaClose, 1
DoCloseExit:
                        pop     eax
                        ret

ToHex:                                           ;eax=value (allow for reverse storage) [edi]=string
                        mov     edi, HexStr
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

CRLF:
                        Write   CRLFDATA, 2
                        ret
;	pop	ecx
;	ret
                        ret
;
;	push 	ecx
;	invoke  LsaEnumerateAccountsWithUserRight, [LSAHANDLE], eax, addr ENUMBUF, addr ENUMCOUNT
;	pop	ecx
;
;	cmp	eax, 0x8000001A		; STATUS_NO_MORE_ENTRIES
;	jz	>SKIP
;	cmp	eax, 0xC0000060		; STATUS_NO_SUCH_PRIVILEGE
;	jz	>SKIP
;	test	eax,eax
;	jnz	>PRIVFAIL
;
;	sub	edx,edx                 ; SID #
;OUTPUTSIDS:
;
;	push	edx
;	call	privname
;	pop	edx
;	push	ecx
;	push    edx
;	invoke  WriteFile, [stdout], addr PrivNameBuf, sizeof PrivNameBuf, addr RCKeep, 0
;	pop	edx
;
;	cmp	edx,[ENUMCOUNT]
;	jz	>NEXT
;SIDLOOP:
;	mov	esi,[ENUMBUF]
;	push	edx
;	invoke	ConvertSidToStringSidA, [esi+edx*4],addr SIDSTR
;	test	eax,eax
;	jz	>BADSID
;	mov	edi,[SIDSTR]
;	sub	ecx,ecx
;	not	ecx
;	sub	eax,eax
;	cld
;	repne   scasb
;	not	ecx
;	dec	ecx
;	invoke  WriteFile, [stdout], [SIDSTR], ecx, addr RCKeep, 0
;	call	CRLF
;	pop	edx
;	inc	edx
;	pop	ecx
;	cmp	edx,[ENUMCOUNT]
;	jb	OUTPUTSIDS
;	inc	ecx
;	jmp	LOOP
;
;NEXT:
;	pop	ecx ; privilege #
;	call	CRLF
;	SKIP:
;	inc	ecx
;	jmp	LOOP
;
;FINISH:
;	invoke  LsaClose, [LSAHANDLE]
;
;	test	eax,eax
;	mov	ecx,sizeof MsgLsaClose
;	mov	esi,addr MsgLsaClose
;	jnz	>FAIL
;
;	xor	eax, eax
;	ret
;
;BADSID:
;	pop	ecx
;	pop	ecx
;	invoke	GetLastError
;	mov	ecx,sizeof MsgConvSID
;	mov	esi,addr MsgConvSID
;	jmp	FAIL
;
;PRIVFAIL:
;	mov	ecx,sizeof MsgLsaEAWUR
;	mov	esi,addr MsgLsaEAWUR
;
;FAIL:
;	push	eax
;	invoke  WriteFile, [stdout], esi, ecx, addr RCKeep, 0
;	pop	eax
;	mov	edi,addr RESULTSTR
;	call	D2sHEXb
;	invoke  WriteFile, [stdout], addr RESULTSTR, sizeof RESULTSTR, addr RCKeep, 0
;	xor	eax,eax
;	inc	eax
;	ret
;
;
;privname:
;	mov	edi, addr PrivNameBuf
;	mov	esi, addr PRIVILEGES
;	xor	edx, edx
;	mov	dx,  w[esi+ecx*8]
;	mov	esi, d[esi+ecx*8+4]
;L101:
;	movsb
;	inc	esi
;	dec	dx
;	dec	dx
;	jnz	L101
;
;	; Pad privilege name with spaces
;	mov	al, 0x20
;L102:
;	cmp	edi, addr PrivNameBufEnd
;	jge	>L103
;	stosb
;	jmp	L102
;
;L103:
;	ret
;
;CRLF:
;	push	ecx
;	invoke  WriteFile, [stdout], addr CRLFDATA, 2, addr RCKeep, 0
;	pop	ecx
;	ret
