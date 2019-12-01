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
#include "Library/BaseCryptLib.h"

STATIC
BOOLEAN
EncVarLibGenEncKey (
  IN VARIABLE_ENCRYPTION_INFO     *VarEncInfo,
  IN UINTN                        EncKeySize,
  OUT UINT8                       *EncKey,
  )
{
  BOOLEAN           Status;
  struct {
    VOID            *Data;
    UINTN           Size;
  }                 InfoGroup[6];
  UINT8             *Info;
  UINTN             InfoSize;
  UINTN             Index;

  //
  // info: Name||':'||Guid||':'||Attr||"VAR_ENC_KEY"
  //
  InfoGroup[0].Size = VarEncInfo->NameSize;
  InfoGroup[0].Data = VarEncInfo->Header.VariableName;

  InfoGroup[1].Size = ENC_KEY_SEP_SIZE;
  InfoGroup[1].Data = ENC_KEY_SEP;

  InfoGroup[2].Size = sizeof (*VarEncInfo->Header.VendorGuid);;
  InfoGroup[2].Data = VarEncInfo->Header.VendorGuid;

  InfoGroup[3].Size = ENC_KEY_SEP_SIZE;
  InfoGroup[3].Data = ENC_KEY_SEP;

  InfoGroup[4].Size = sizeof (VarEncInfo->Header.Attributes);
  InfoGroup[4].Data = &VarEncInfo->Header.Attributes;

  InfoGroup[5].Size = ENC_KEY_NAME_SIZE;
  InfoGroup[5].Data = ENC_KEY_NAME;

  for (InfoSize = 0, Index = 0; Index < ARRAY_SIZE (InfoGroup); ++Index) {
    InfoSize += InfoGroup[Index].Size;
  }

  Info = AllocatePool (InfoSize);
  if (Info == NULL) {
    ASSERT (Info != NULL);
    return FALSE;
  }

  for (InfoSize, Index = 0; Index < ARRAY_SIZE (InfoGroup); ++Index) {
    CopyMem (Info + InfoSize, InfoGroup[Index].Data, InfoGroup[Index].Size);
    InfoSize += InfoGroup[Index].Size;
  }

  Status = HkdfSha256ExtractAndExpand (
             VarEncInfo->Key,
             VarEncInfo->KeySize,
             NULL, 
             0,
             Info,
             InfoSize,
             EncKeyKey,
             EncKeySize
             );

  FreePool (Info);

  return Status;
}

BOOLEAN
EncVarLibGenIvec (
  OUT UINT8           *InitVector,
  IN  UINTN           Size
  )
{
  UINT64        Data[2];
  UINTN         Count;
  UINT8         *Buffer;

  Buffer = ALIGN_POINTER (InitVector, sizeof (UINT64));
  Count = Buffer - InitVector;

  if (Count != 0) {
    Count += sizeof (UINT64);
    if (!GetRandomNumber128 (Data)) {
      return FALSE;
    }

    CopyMem (InitVector, &Data, Count);
    Size -= Count;
  }

  Count = sizeof (UINT64) * 2;
  while (Size >= Count) {
    if (!GetRandomNumber128 ((UINT64 *)Buffer)) {
      return FALSE;
    }

    Buffer  += Count;
    Size    -= Count;
  }

  if (Count != 0) {
    if (!GetRandomNumber128 (Data)) {
      return FALSE;
    }

    CopyMem (Buffer, &Data, Count);
  }

  return TRUE;
}

EFI_STATUS
EFIAPI
EncryptVariable (
  IN OUT VARIABLE_ENCRYPTION_INFO     *VarEncInfo
  )
{
  VOID                          *AesContext;
  UINT8                         EncKey[ENC_KEY_SIZE];
  UINT8                         Ivec[ENC_IVEC_SIZE];
  UINT8                         *PlainData;
  UINTN                         PlainDataSize;
  VARIABLE_ENCRYPTION_HEADER    *CipherData;
  UINTN                         CipherDataSize;
  EFI_STATUS                    Status;

  Status      = EFI_ABORTED;
  AesContext  = NULL;
  PlainData   = NULL;
  CipherData  = NULL;

  if (VarEncInfo->Header.VariableName == NULL ||
      VarEncInfo->NameSize == 0 ||
      VarEncInfo->Header.VendorGuid == NULL ||
      VarEncInfo->Key == NULL ||
      VarEncInfo->PlainData == NULL ||
      VarEncInfo->PlainDataSize == 0) {
    ASSERT (VarEncInfo->Header.VariableName != NULL);
    ASSERT (VarEncInfo->Header.VendorGuid != NULL);
    ASSERT (VarEncInfo->Key != NULL);
    ASSERT (VarEncInfo->PlainData != NULL);
    ASSERT (VarEncInfo->PlainDataSize != 0);
    return EFI_INVALID_PARAMETER;
  }

  if (!EncVarLibGenEncKey (VarEncInfo, ENC_KEY_SIZE, EncKey)) {
    ASSERT (FALSE);
    return EFI_ABORTED;
  }

  if (!EncVarLibGenIvec (Ivec, ENC_IVEC_SIZE)) {
    ASSERT (FALSE);
    return EFI_ABORTED;
  }

  AesContext = AllocateZeroPool (AesGetContextSize ());
  if (AesContext == NULL) {
    ASSERT (AesContext != NULL);
    return EFI_OUT_OF_RESOURCES;
  }

  if (!AesInit (AesContext, EncKey, EncKeySize)) {
    ASSERT (FALSE);
    goto Done;
  }

  //
  // Plain variable data must also be multiple of ENC_BLOCK_SIZE.
  //
  if ((VarEncInfo->PlainDataSize % ENC_BLOCK_SIZE) != 0) {
    PlainDataSize = ALIGN_VALUE (VarEncInfo->PlainDataSize, ENC_BLOCK_SIZE);
    PlainData     = AllocateZeroPool (PlainDataSize);

    if (PlainData == NULL) {
      ASSERT (PlainData != NULL)
      goto Done;
    }
  } else {
    PlainDataSize = VarEncInfo->PlainDataSize;
    PlainData     = PlainData;
  }

  CipherDataSize = sizeof (VARIABLE_ENCRYPTION_HEADER) +
                   AES_CIPHER_DATA_SIZE (VarEncInfo->PlainDataSize);
  CipherData = (VARIABLE_ENCRYPTION_HEADER *)AllocatePool (CipherDataSize);
  if (CipherData == NULL) {
    ASSERT (CipherData != NULL);
    goto Done;
  }

  CopyMem (PlainData, VarEncInfo->PlainData, VarEncInfo->PlainDataSize);
  if (AesCbcEncrypt (AesContext, PlainData, PlainDataSize, Ivec,
                     (UINT8 *)(CipherData + 1))) {
    //
    // Keep the IV for decryption.
    //
    CopyMem (CipherData->KeyIvec, Ivec, ENC_BLOCK_SIZE);
    CipherData->CipherDataSize    = CipherDataSize;
    CipherData->PlainDataSize     = VarEncInfo->PlainDataSize;
    CipherData->DataType          = ENC_TYPE_AES;
    CipherData->HeaderSize        = sizeof (VARIABLE_ENCRYPTION_HEADER);

    VarEncInfo->CipherData        = CipherData;
    VarEncInfo->CipherDataSize    = CipherDataSize;
    VarEncInfo->CipherHeaderSize  = sizeof (VARIABLE_ENCRYPTION_HEADER);
    VarEncInfo->CipherDataType    = ENC_TYPE_AES;

    //
    // Stop freeing cipher data buffer here.
    //
    CipherData                    = NULL;
  } else {
    VarEncInfo->CipherData        = NULL;
    VarEncInfo->CipherDataSize    = 0;
    VarEncInfo->CipherHeaderSize  = 0;
    VarEncInfo->CipherDataType    = ENC_TYPE_NULL;
  }

  Status = EFI_SUCCESS;

Done:
  FREE_POOL (AesContext);
  FREE_POOL (PlainData);
  FREE_POOL (CipherData);

  return Status;
}

EFI_STATUS
EFIAPI
DecryptVariable (
  IN OUT VARIABLE_ENCRYPTION_INFO     *VarEncInfo
  )
{
  VOID                          *AesContext;
  UINT8                         EncKey[ENC_KEY_SIZE];
  UINT8                         *PlainData;
  EFI_STATUS                    Status;

  Status      = EFI_ABORTED;
  AesContext  = NULL;
  PlainData   = NULL;

  if (VarEncInfo->Header.VariableName == NULL ||
      VarEncInfo->NameSize == 0 ||
      VarEncInfo->Header.VendorGuid == NULL ||
      VarEncInfo->Key == NULL ||
      VarEncInfo->CipherData == NULL ||
      VarEncInfo->CipherDataSize <= sizeof (VARIABLE_ENCRYPTION_HEADER)) {
    ASSERT (VarEncInfo->Header.VariableName != NULL);
    ASSERT (VarEncInfo->Header.VendorGuid != NULL);
    ASSERT (VarEncInfo->Key != NULL);
    ASSERT (VarEncInfo->CipherData != NULL);
    ASSERT (VarEncInfo->CipherDataSize != 0);
    ASSERT (VarEncInfo->CipherDataSize > sizeof (VARIABLE_ENCRYPTION_HEADER));
    return EFI_INVALID_PARAMETER;
  }

  //
  // Sanity check of cipher header.
  //
  CipherData = (VARIABLE_ENCRYPTION_HEADER *)VarEncInfo->CipherData + 1;
  if (CipherData->DataType != ENC_TYPE_AES ||
      CipherData->CipherDataSize == 0 ||
      (CipherData->CipherDataSize % ENC_BLOCK_SIZE) != 0 ||
      CipherData->PlainDataSize == 0 ||
      CipherData->PlainDataSize > CipherData->CipherDataSize) {
    ASSERT (CipherData->DataType == ENC_TYPE_AES);
    ASSERT (CipherData->CipherDataSize > 0);
    ASSERT ((CipherData->CipherDataSize % ENC_BLOCK_SIZE) == 0);
    ASSERT (CipherData->PlainDataSize > 0);
    ASSERT (CipherData->PlainDataSize <= CipherData->CipherDataSize);
    return EFI_VOLUME_CORRUPTED;
  }

  if (!EncVarLibGenEncKey (VarEncInfo, ENC_KEY_SIZE, EncKey)) {
    ASSERT (FALSE);
    return EFI_ABORTED;
  }

  AesContext = AllocateZeroPool (AesGetContextSize ());
  if (AesContext == NULL) {
    ASSERT (AesContext != NULL);
    return EFI_OUT_OF_RESOURCES;
  }

  if (!AesInit (AesContext, EncKey, ENC_KEY_SIZE)) {
    ASSERT (FALSE);
    goto Done;
  }

  //
  // Decrypted data must be same size as cipher data.
  //
  PlainData = AllocateZeroPool (VarEncInfo->CipherDataSize);
  if (PlainData == NULL) {
    ASSERT (PlainData != NULL)
    goto Done;
  }

  if (AesCbcDecrypt (AesContext, (UINT8 *)(CipherData + 1),
                     CipherData->CipherDataSize, CipherData->KeyIvec,
                     PlainData)) {
    if (VarEncInfo->DecryptInPlace) {
      //
      // Use the same buffer of cipher data to store the deciphered data. Keep
      // the cipher header part.
      //
      VarEncInfo->PlainData = (UINT8 *)(CipherData + 1);
      CipherData->DataType  = ENC_TYPE_NULL;

      CopyMem (VarencInfo->PlainData, PlainData, CipherData->PlainDataSize);
    } else {
      VarEncInfo->PlainData = PlainData;
      PlainData             = NULL; // No need to free buffer here then.
    }

    VarEncInfo->CipherHeaderSize  = sizeof (VARIABLE_ENCRYPTION_HEADER);
    VarEncInfo->CipherDataType    = ENC_TYPE_AES;
    VarEncInfo->PlainDataSize     = CipherData->PlainDataSize;

    Status = EFI_SUCCESS;
  } else {
    VarEncInfo->PlainData         = NULL;
    VarEncInfo->PlainDataSize     = 0;

    Status = EFI_COMPROMISED_DATA;
  }

Done:
  FREE_POOL (AesContext);
  FREE_POOL (PlainData);
  FREE_POOL (CipherData);

  return Status;
}

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
    // The data must have been decrypted. Just skip the cipher header to get
    // the decrypted data.
    //
    VarEncInfo->PlainData = (UINT8 *)VarEncInfo->CipherData + EncHeader->HeaderSize;
  } else {
    //
    // The data is encrypted. Return NULL to let caller know.
    //
    VarEncInfo->PlainData = NULL;
  }

  VarEncInfo->PlainDataSize    = EncHeader->PlainDataSize;
  VarEncInfo->CipherDataType   = EncHeader->DataType;
  VarEncInfo->CipherDataSize   = EncHeader->CipherDataSize;
  VarEncInfo->CipherHeaderSize = EncHeader->HeaderSize

  return EFI_SUCCESS;
}

