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
extern      ConvertSidToStringSidA
extern      GetLastError

            SECTION .data

sHEXb:                  db      "0123456789ABCDEF"
CRLFDATA:               db      13, 10
LSAHANDLE:              dd      -1

LsaUnicodeStr:
StrLen:                 dw      0
BufLen:                 dw      PrivNameBufWEnd-PrivNameBufW
PrivString:             dd      PrivNameBufW

PrivNameBufA:           db      'Se'
PrivNameA:              times   80 db 0
PrivNameBufAEnd:

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
                        constr  MsgBadSID,        '??? ConvertSidToStringSid: '
                        constr  Tab,              9

%include 'priv.asm'

                        SECTION    .bss
stdout                  resd    1
HexStr                  resb    8

RCKeep                  resd    1
LSAOBJ                  resd    5
ENUMCOUNT               resd    1
ENUMBUF                 resd    1
SIDSTR                  resd    1

PrivNameBufW:           resw    80
PrivNameBufWEnd:

PrivNameALen:           resd    1

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
                        inc     esi
                        mov     edi, PrivNameA
ascii:                  repnz   movsb
                        mov     esi, [SuffixPtr]
                        mov     ecx, [SuffixLen]
                        repnz   movsb
                        sub     edi, PrivNameBufA
                        mov     [PrivNameALen], edi

                        mov     ecx, edi        ; ASCII string length
                        mov     esi, PrivNameBufA
                        mov     edi, PrivNameBufW
utf16:                  movsb
                        inc     edi
                        dec     ecx
                        jnz     utf16
                        sub     edi, PrivNameBufW
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

                        xor     edx, edx
SIDLoop:
                        cmp     edx, [ENUMCOUNT]
                        jz      Skip

                        push    edx
                        mov     esi, [ENUMBUF]
                        push    SIDSTR
                        push    dword [esi+edx*4]

                        Write   PrivNameBufA, dword [PrivNameALen]
                        Write   Tab, Tab_Size
                        call    [ConvertSidToStringSidA]
                        test    eax, eax
                        jz      BadSID

                        mov     edi, [SIDSTR]
                        sub     ecx, ecx
                        not     ecx
                        sub     eax,eax
                        cld
                        repne   scasb
                        not     ecx
                        dec     ecx
                        Write   dword [SIDSTR], ecx
DoneSID:
                        call    CRLF
                        pop     edx
                        inc     edx
                        cmp     edx, [ENUMCOUNT]
                        jnz     SIDLoop

Skip:                   pop     esi
Next:                   inc     esi
                        inc     esi
                        inc     esi
                        inc     esi
                        jmp     PRIVLOOP

BadSID:
                        Write   MsgBadSID, MsgBadSID_Size
                        call    [GetLastError]
                        call    ToHex
                        Write   HexStr, 8
                        jmp     DoneSID

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
