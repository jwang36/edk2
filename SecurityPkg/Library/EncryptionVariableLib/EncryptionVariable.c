/** @file
  The common variable operation routines shared by DXE_RUNTIME variable
  module and DXE_SMM variable module.

  Caution: This module requires additional review when modified.
  This driver will have external input - variable data. They may be input in SMM mode.
  This external input must be validated carefully to avoid security issue like
  buffer overflow, integer overflow.

  VariableServiceGetNextVariableName () and VariableServiceQueryVariableInfo() are external API.
  They need check input parameter.

  VariableServiceGetVariable() and VariableServiceSetVariable() are external API
  to receive datasize and data buffer. The size should be checked carefully.

  VariableServiceSetVariable() should also check authenticate data to avoid buffer overflow,
  integer overflow. It should also check attribute to avoid authentication bypass.

Copyright (c) 2019, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "Guid/VariableFormat.h"
#include "Library/EncryptionVariableLib.h"
#include "Library/ProtectedVariableLib.h"

EFI_STATUS
EFIAPI
GetCipherInfo (
  IN VARIABLE_ENCRYPTION_INFO     *VarEncInfo
  )
{
  VARIABLE_ENCRYPTION_HEADER        *EncHeader;

  if (VarEncInfo->CipherData == NULL || VarEncInfo->CipherDataSize == 0) {
    return EFI_INVALID_PARAMETER;
  }

  EncHeader = (VARIABLE_ENCRYPTION_HEADER *)VarEncInfo->CipherData;
  if (EncHeader->DataType == ENC_TYPE_NULL) {
    //
    // The data must be decrypted.
    //
    VarEncInfo->PlainData = (UINT8 *)VarEncInfo->CipherData + EncHeader->HeaderSize;
  } else {
    VarEncInfo->PlainData = NULL;
  }

  VarEncInfo->PlainDataSize    = EncHeader->PlainDataSize;
  VarEncInfo->CipherDataType   = EncHeader->DataType;
  VarEncInfo->CipherDataSize   = EncHeader->CipherDataSize;
  VarEncInfo->CipherHeaderSize = EncHeader->HeaderSize

  return EFI_SUCCESS;
}

