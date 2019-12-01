/** @file
  Emulation instance of VariableKeyLib for test purpose. Don't use it in real product.

Copyright (c) 2019, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Library/DebugLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/RngLib.h>

STATIC UINT64            mRootKey[4] = {0x2AB74E453DEA448A, 0x822964AEA9EF2EC3,
                                        0xDB7D36EF6030438F, 0xA635C9D75CC64767};
STATIC BOOLEAN           mKeyInterfaceLocked = FALSE;

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
  )
{
  ASSERT (VariableRootKey != NULL);
  ASSERT (VariableRootKeySize != NULL);

  if (mKeyInterfaceLocked) {
    return EFI_ACCESS_DENIED;
  }

  *VariableRootKey      = &mRootKey;
  *VariableRootKeySize  = sizeof (mRootKey);

  return EFI_SUCCESS;
}

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
  )
{
  if (mKeyInterfaceLocked) {
    return EFI_ACCESS_DENIED;
  }

  if (!GetRandomNumber128 (mRootKey) ||
      !GetRandomNumber128 (mRootKey + 2)) {
    return EFI_DEVICE_ERROR;
  }

  return EFI_SUCCESS;
}

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
  )
{
  mKeyInterfaceLocked = TRUE;
  return EFI_SUCCESS;
}

