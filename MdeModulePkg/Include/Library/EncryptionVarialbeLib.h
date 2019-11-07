/** @file
  Provides services to initialize and process authenticated variables.

Copyright (c) 2019, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _PROTECTED_VARIABLE_LIB_H_
#define _PROTECTED_VARIABLE_LIB_H_

#include <Protocol/VarCheck.h>

/**
  Initialization for authenticated varibale services.
  If this initialization returns error status, other APIs will not work
  and expect to be not called then.

  @param[in]  ProtectedVarLibContextIn   Pointer to input auth variable lib context.
  @param[out] ProtectedVarLibContextOut  Pointer to output auth variable lib context.

  @retval EFI_SUCCESS               Function successfully executed.
  @retval EFI_INVALID_PARAMETER     If ProtectedVarLibContextIn == NULL or ProtectedVarLibContextOut == NULL.
  @retval EFI_OUT_OF_RESOURCES      Fail to allocate enough resource.
  @retval EFI_UNSUPPORTED           Unsupported to process authenticated variable.

**/
EFI_STATUS
EFIAPI
EncryptVariable (
  IN CHAR16            *VariableName,
  IN EFI_GUID          *VendorGuid,
  IN UINT32            Attribute,
  IN VOID              *PlainData,
  IN UINTN             PlainDataSize,
  OUT VOID             **CipherData, // Pointer to VARIABLE_ENC_DATA_HEADER
  OUT UINTN            *CipherDataSize
  );

/**
  Process variable with EFI_VARIABLE_TIME_BASED_PROTECTEDENTICATED_WRITE_ACCESS set.

  @param[in] VariableName           Name of the variable.
  @param[in] VendorGuid             Variable vendor GUID.
  @param[in] Data                   Data pointer.
  @param[in] DataSize               Size of Data.
  @param[in] Attributes             Attribute value of the variable.

  @retval EFI_SUCCESS               The firmware has successfully stored the variable and its data as
                                    defined by the Attributes.
  @retval EFI_INVALID_PARAMETER     Invalid parameter.
  @retval EFI_WRITE_PROTECTED       Variable is write-protected.
  @retval EFI_OUT_OF_RESOURCES      There is not enough resource.
  @retval EFI_SECURITY_VIOLATION    The variable is with EFI_VARIABLE_TIME_BASED_PROTECTEDENTICATED_WRITE_ACESS
                                    set, but the AuthInfo does NOT pass the validation
                                    check carried out by the firmware.
  @retval EFI_UNSUPPORTED           Unsupported to process authenticated variable.

**/
EFI_STATUS
EFIAPI
DecryptVariable (
  IN CHAR16            *VariableName,
  IN EFI_GUID          *VendorGuid,
  IN UINT32            Attribute,
  IN VOID              *CipherData, // Pointer to VARIABLE_ENC_DATA_HEADER
  IN UINTN             CipherDataSize,
  OUT VOID             **PlainData,
  OUT UINTN            *PlainDataSize
  );


EFI_STATUS
EFIAPI
GetCipherInfo (
  IN VOID              *Data, // Pointer to VARIABLE_ENC_DATA_HEADER
  IN UINTN             DataSize,
  OUT UINT32           *KeyType OPTIONAL,
  OUT UINTN            *CipherDataSize OPTIONAL,
  OUT UINTN            *PlainDataSize OPTIONAL
  );

#endif
