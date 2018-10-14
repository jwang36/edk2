/** @file
 Base Stack Check library for MSFT toolchains compiler options: /GS, RTCs.

Copyright (c) 2018, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials are licensed and made available under
the terms and conditions of the BSD License that accompanies this distribution.
The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php.

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Base.h>

#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/PcdLib.h>

//
// cookie value that is inserted by the MSFT compiler into the stack frame.
//
extern UINTN __security_cookie;

//
// Data structure used by MSFT compiler to record local variable information.
//

typedef struct _RTC_vardesc {
  int   Addr;
  int   Size;
  char  *Name;
} _RTC_vardesc;

typedef struct _RTC_framedesc {
  int           VarCount;
  _RTC_vardesc  *Variables;
} _RTC_framedesc;

#define RTC_STACK_CHECK_COOKIE  0xCCCCCCCC

/**
  Function called upon unexpected stack pointer change.

  @param Ip       Instruction address where the check happened.

**/
VOID
__cdecl
_RTC_Failure (
  VOID    *Ip
  )
{
  DEBUG ((EFI_D_ERROR, "\nSTACK FAULT: Suspicious stack pointer (IP:%p).\n\n", Ip));

  //
  // Generate a Breakpoint, DeadLoop, or NOP based on PCD settings even if
  // BaseDebugLibNull is in use.
  //
  if ((PcdGet8 (PcdDebugPropertyMask) & DEBUG_PROPERTY_ASSERT_BREAKPOINT_ENABLED) != 0) {
    CpuBreakpoint ();
  } else {
    //
    // Usually the boot should stop here if check failure. Due to the fact
    // that the normal Stack Switch happened in boot will also fail the stack
    // pointer check. So no dead loop here.
    //
  }
  return;
}

/**
  Function reporting stack buffer overlow.

  @param Name     Local varible name.
  @param Ip       Instruction address where the check happened.

**/
STATIC
VOID
_RTC_StackFailure (
  CHAR8   *Name,
  VOID    *Ip
  )
{
  DEBUG ((EFI_D_ERROR, "\nSTACK FAULT: Local variable '%a' overflow (IP:%p).\n\n", Name, Ip));

  //
  // Generate a Breakpoint, DeadLoop, or NOP based on PCD settings even if
  // BaseDebugLibNull is in use.
  //
  if ((PcdGet8 (PcdDebugPropertyMask) & DEBUG_PROPERTY_ASSERT_BREAKPOINT_ENABLED) != 0) {
    CpuBreakpoint ();
  } else if ((PcdGet8 (PcdDebugPropertyMask) & DEBUG_PROPERTY_ASSERT_DEADLOOP_ENABLED) != 0) {
   CpuDeadLoop ();
  }
  return ;
}

/**
  Function called upon stack buffer overflow. (/RTCs)

  @param _Esp     Stack frame pointer.
  @param _Fd      Pointer to local variable information.

**/
VOID
__fastcall
_RTC_CheckStackVars (
  VOID            *_Esp,
  _RTC_framedesc  *_Fd
  )
{
  INTN      Index;
  UINT8     *Addr;

  for (Index = 0; Index < _Fd->VarCount; Index++) {
    Addr = (UINT8 *)_Esp + _Fd->Variables[Index].Addr - sizeof(UINT32);
    if (*(UINT32 *)Addr != RTC_STACK_CHECK_COOKIE) {
      _RTC_StackFailure (_Fd->Variables[Index].Name, RETURN_ADDRESS(0));
    }

    Addr = (UINT8 *)_Esp + _Fd->Variables[Index].Addr + _Fd->Variables[Index].Size;
    if (*(UINT32 *)Addr != RTC_STACK_CHECK_COOKIE) {
      _RTC_StackFailure (_Fd->Variables[Index].Name, RETURN_ADDRESS(0));
    }
  }
}

/**
  Function required by linker but not implemented by firmware image loader. (/RTCs)

**/
VOID
__cdecl
_RTC_Shutdown (
  VOID
  )
{
  return;
}

/**
  Function required by linker but not implemented by firmware image loader. (/RTCs)

**/
VOID
__cdecl
_RTC_InitBase (
  VOID
  )
{
  return;
}


/**
  Function called upon stack frame overflow detected. (/GS)

  @param StackCookie    Actual cookie value got from stack boundary.
  @param Ip             Instruction address where the check happened.

**/
NORETURN
VOID
__cdecl
__report_gsfailure (
  UINTN     StackCookie,
  VOID      *Ip
  )
{
  DEBUG ((EFI_D_ERROR, "\nSTACK FAULT: Stack overflow check failed in cookie checker (IP:%p).\n\n", Ip));

  //
  // Generate a Breakpoint, DeadLoop, or NOP based on PCD settings even if
  // BaseDebugLibNull is in use.
  //
  if ((PcdGet8 (PcdDebugPropertyMask) & DEBUG_PROPERTY_ASSERT_BREAKPOINT_ENABLED) != 0) {
    CpuBreakpoint ();
  } else if ((PcdGet8 (PcdDebugPropertyMask) & DEBUG_PROPERTY_ASSERT_DEADLOOP_ENABLED) != 0) {
   CpuDeadLoop ();
  }
}

/**
  Function called upon failure at local array range check . (/GS)

**/
NORETURN
VOID
__cdecl
__report_rangecheckfailure (
  VOID
  )
{
  DEBUG((EFI_D_ERROR, "\nSTACK FAULT: Range check check failed in cookie checker.\n\n"));

  //
  // Generate a Breakpoint, DeadLoop, or NOP based on PCD settings even if
  // BaseDebugLibNull is in use.
  //
  if ((PcdGet8 (PcdDebugPropertyMask) & DEBUG_PROPERTY_ASSERT_BREAKPOINT_ENABLED) != 0) {
    CpuBreakpoint ();
  } else if ((PcdGet8 (PcdDebugPropertyMask) & DEBUG_PROPERTY_ASSERT_DEADLOOP_ENABLED) != 0) {
   CpuDeadLoop ();
  }
}

/**
  Function required by linker but not implemented by firmware image loader. (/GS)

**/
VOID
__GSHandlerCheck (
  VOID
  )
{
  return;
}

