/** @file
  Header file for the Variable Key Library.

Copyright (c) 2019, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _VARIABLE_KEY_LIB_H_
#define _VARIABLE_KEY_LIB_H_

#include <Uefi.h>

/**
  Retrieves the variable root key.

  @param[in]    VariableRootKey         A pointer to pointer for the variable root key buffer.
  @param[in]    VariableRootKeySize     The size in bytes of the variable root key.

  @retval       EFI_SUCCESS             The variable root key was retrieved successfully.
  @retval       EFI_DEVICE_ERROR        An error occurred while attempting to get the variable root key.
  @retval       EFI_ACCESS_DENIED       The function was invoked after locking the key interface.
  @retval       EFI_UNSUPPORTED         The variable root key is not supported in the current boot configuration.
**/
EFI_STATUS
EFIAPI
GetVariableRootKey (
  OUT   VOID    **VariableRootKey,
  OUT   UINTN   *VariableRootKeySize
  );

/**
  Regenerates the variable root key.

  @retval       EFI_SUCCESS             The variable root key was regenerated successfully.
  @retval       EFI_DEVICE_ERROR        An error occurred while attempting to regenerate the root key.
  @retval       EFI_ACCESS_DENIED       The function was invoked after locking the key interface.
  @retval       EFI_UNSUPPORTED         Key regeneration is not supported in the current boot configuration.
**/
EFI_STATUS
EFIAPI
RegenerateKey (
  VOID
  );

/**
  Locks the regenerate key interface.

  @retval       EFI_SUCCESS             The key interface was locked successfully.
  @retval       EFI_UNSUPPORTED         Locking the key interface is not supported in the current boot configuration.
  @retval       Others                  An error occurred while attempting to lock the key interface.
**/
EFI_STATUS
EFIAPI
LockKeyInterface (
  VOID
  );

#endif