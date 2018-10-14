;------------------------------------------------------------------------------ ;
; Copyright (c) 2018, Intel Corporation. All rights reserved.<BR>
; This program and the accompanying materials
; are licensed and made available under the terms and conditions of the BSD License
; which accompanies this distribution.  The full text of the license may be found at
; http://opensource.org/licenses/bsd-license.php.
;
; THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
; WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
;
; Module Name:
;
;   StackCheckStubAsm.nasm
;
; Abstract:
;
;   Stub globals and functions for compiler options /GS, /RTCs
;
; Notes:
;
;------------------------------------------------------------------------------

;
; __declspec(noreturn) void __cdecl __report_gsfailure(UINTN cookie, void *ip);
;
extern __report_gsfailure

DEFAULT REL

SECTION .data

;
; UINTN __security_cookie;
;
global __security_cookie
__security_cookie:
    DQ     0CFE3FE6A3F5C5A88h

SECTION .text

;
; void __fastcall __security_check_cookie(UINTN cookie)
;
;   Note: __fastcall calling convention uses ecx/edx to pass first two parameters
;
global __security_check_cookie
__security_check_cookie:
    cmp         rcx, qword [__security_cookie]
    je          .1
    mov         rdx, [esp]  ; pass return address as the second parameter
    call        __report_gsfailure
.1
    ret

