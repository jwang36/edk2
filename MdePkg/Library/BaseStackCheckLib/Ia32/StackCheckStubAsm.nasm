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
extern ___report_gsfailure
;
; void __cdecl _RTC_Failure (void *Ip);
;
extern __RTC_Failure

SECTION .data

;
; UINTN __security_cookie;
;
global ___security_cookie
___security_cookie:
    DW     987974FAh

SECTION .text

;
; void __fastcall __security_check_cookie(UINTN cookie)
;
;   Note: __fastcall calling convention uses ecx/edx to pass first two parameters
;
global @__security_check_cookie@4
@__security_check_cookie@4:
    push        ebp
    mov         ebp, esp
    cmp         ecx, [___security_cookie]
    je          .1
    push        dword [ebp] ; pass return address as the second parameter
    push        ecx         ; cookie value in stack is the first parameter
    call        ___report_gsfailure
.1:
    mov         esp, ebp
    pop         ebp
    ret

;
; void __declspec(naked) __cdecl _RTC_CheckEsp(void)
;
global __RTC_CheckEsp
__RTC_CheckEsp:
    push        ebp
    mov         ebp, esp
    je         .1
    push       dword [ebp]  ; pass return address to __RTC_Failure
    call        __RTC_Failure
.1:
    mov         esp, ebp
    pop         ebp
    ret

