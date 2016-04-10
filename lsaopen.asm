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
extern      LsaEnumeratePrivileges
extern      ConvertSidToStringSidA
extern      GetLastError

                        SECTION .data

sHEXb:                  db      "0123456789ABCDEF"
CRLFDATA:               db      13, 10
LSAHANDLE:              dd      -1
PrivEnumCtx             dd      0

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
                        constr  MsgLsaEnumPriv,   'LsaEnumeratePrivileges: '
                        constr  MsgBadSID,        '??? ConvertSidToStringSid: '
                        constr  Tab,              9

                        SECTION    .bss
stdout                  resd    1
HexStr                  resb    8

RCKeep                  resd    1
LSAOBJ                  resd    5
ENUMCOUNT               resd    1
ENUMBUF                 resd    1
SIDSTR                  resd    1

PrivEnumBuf             resd    1
PrivEnumCount           resd    1

PrivNameALen:           resd    1
PrivNameBufA:           resb   80
PrivNameBufAEnd:


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

                        Fail?   MsgLsaOpenPolicy, 0

                        push    PrivEnumCount
                        push    dword 2048
                        push    PrivEnumBuf
                        push    PrivEnumCtx
                        push    dword [LSAHANDLE]
                        Call    [LsaEnumeratePrivileges]
                        Fail?   MsgLsaEnumPriv, 0

                        mov     eax,[PrivEnumBuf]
                        call    ToHex
                        Write   HexStr, 8
                        call    CRLF

                        xor     ecx, ecx
PRIVLOOP:
                        cmp     ecx, [PrivEnumCount]
                        jz      Finish

                        mov     esi, [PrivEnumBuf]
                        push    ecx
                        shl     ecx, 4              ; Array of PPOLICY_PRIVILEGE_DEFINITIONs
                        lea     eax, [esi + ecx]    ; contains LSA_UNICODE_STRING and 64-bit LUID

                        push    ENUMCOUNT           ; Arguments for LsaEnumerateAccountsWithUserRight
                        push    ENUMBUF
                        push    eax
                        push    dword [LSAHANDLE]

                        xor     ecx, ecx
                        mov     esi, eax
                        mov     cx,  [esi+2]        ; Actual length
                        mov     eax, ecx
                        mov     esi, [esi+4]
                        shr     eax, 1
                        mov     [PrivNameALen], eax
                        mov     edi, PrivNameBufA
ascii:                  movsb
                        inc     esi
                        dec     ecx
                        jnz     ascii

                        call    [LsaEnumerateAccountsWithUserRight]
                        cmp     eax, 0x8000001A     ; STATUS_NO_MORE_ENTRIES
                        jz      Skip
                        cmp     eax, 0xC0000060     ; STATUS_NO_SUCH_PRIVILEGE
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

Skip:                   pop     ecx
                        inc     ecx
                        cmp     ecx, [PrivEnumCount]
                        jnz     PRIVLOOP

Finish:
                        xor     eax, eax
                        jmp     DoClose

BadSID:
                        Write   MsgBadSID, MsgBadSID_Size
                        call    [GetLastError]
                        call    ToHex
                        Write   HexStr, 8
                        jmp     DoneSID

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
