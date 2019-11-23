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

PROTECTED_VARIABLE_CONTEXT_IN   *mVariableContextIn       = NULL;
PROTECTED_VARIABLE_CONTEXT_OUT  *mVariableContextOut      = NULL;
VARIABLE_STORE_HEADER           *mProtectedVariableCache  = NULL;

EFI_TIME                        mDefaultTimeStamp = {0,0,0,0,0,0,0,0,0,0,0};

BOOLEAN
UpdateVariableMetadataHmac (
  IN  VOID                    Context,
  IN  AUTH_VARIABLE_INFO      *VarInfo,
  IN  VOID                    *CipherData,
  IN  UINT32                  CipherDataSize
  )
{
  VOID            *Buffer[12];
  VOID            BufferSize[12];
  BOOLEAN         Status;

  //
  // HMAC (":" || VariableName)
  //
  Buffer[0]       = ":";
  BufferSize[0]   = 1;

  Buffer[1]       = VarInfo->VariableName;
  BufferSize[1]   = StrSize (VarInfo->VariableName);

  //
  // HMAC (":" || VendorGuid || Attributes || DataSize)
  //
  Buffer[2]       = ":";
  BufferSize[2]   = 1;

  Buffer[3]       = VarInfo->VendorGuid;
  BufferSize[3]   = sizeof (EFI_GUID);

  Buffer[4]       = &VarInfo->Attributes;
  BufferSize[4]   = sizeof (VarInfo->Attributes);

  Buffer[5]       = &CipherDataSize;
  BufferSize[5]   = sizeof (CipherDataSize);

  //
  // HMAC (":" || CipherData)
  //
  Buffer[6]       = ":";
  BufferSize[6]   = 1;

  Buffer[7]       = CipherData;
  BufferSize[7]   = CipherDataSize;

  //
  // HMAC (":" || PubKeyIndex || AuthMonotonicCount || TimeStamp)
  //
  Buffer[8]       = ":";
  BufferSize[8]   = 1;

  Buffer[9]       = &VarInfo->PubKeyIndex;
  BufferSize[9]   = sizeof (VarInfo->PubKeyIndex);

  Buffer[10]      = &VarInfo->MonotonicCount;
  BufferSize[10]  = sizeof (VarInfo->MonotonicCount);

  Buffer[11]      = (VarInfo->TimeStamp != NULL) ? VarInfo->TimeStamp :
                                                   &mDefaultTimeStamp;
  BufferSize[11]  = sizeof (EFI_TIME);

  for (Index = 0; Index < ARRAY_SIZE (Buffer); ++Index) {
    Status = HmacSha256Update (Context, Buffer[Index], BufferSize[Index]);
    if (!Status) {
      ASSERT (FALSE);
      return FALSE;
    }
  }

  return TRUE;
}

EFI_STATUS
RefreshVariableMetadataHmac (
  VARIABLE_ENCRYPTION_INFO          *VarEncInfo
  )
{
  EFI_STATUS                Status;
  UINT8                     HmacValue[SHA256_DIGEST_SIZE];
  UINT32                    Counter;
  VARIABLE_HEADER           *Variable;
  VARIABLE_STORE_HEADER     *VarStoreHeader;
  AUTH_VARIABLE_INFO        VarInfo;
  BOOLEAN                   HmacStatus;

  //
  // Force marking old HmacVariableName as VAR_IN_DELETED_TRANSITION.
  //
  Status = mVariableContextIn->UpdateVariableStorage (
                                 METADATA_HMAC_VARIABLE_NAME,
                                 METADATA_HMAC_VARIABLE_GUID,
                                 VAR_IN_DELETED_TRANSITION
                                 );
  if (EFI_ERROR (Status)) {
    ASSERT_EFI_ERROR (Status);
    return Status;
  }

  Status = RequestMonotonicCounter (DEFAULT_COUNTER_INDEX, &Counter);
  if (EFI_ERROR (Status)) {
    ASSERT_EFI_ERROR (Status);
    return Status;
  }
  Counter += 1;

  //
  // Re-calcuate HMAC for all valid variables
  //
  Context = HmacSha256New ();
  if (Context == NULL) {
    ASSERT (Context != NULL);
    return EFI_OUT_OF_RESOURCES;
  }

  Status = EFI_ABORTED;
  if (!HmacSha256Init (Context,
                       mVariableContextOut->MetaDataHmacKey,
                       mVariableContextOut->MetaDataHmacKeySize)) {
    ASSERT (FALSE);
    goto Done;
  }

  //
  // HMAC (RpmcMonotonicCounter)
  //
  if (!HmacSha256Update (Context, &Counter, sizeof (Counter))) {
    ASSERT (FALSE);
    goto Done;
  }

  //
  // HMAC (|| Var1 || Var2 || ... || VarN)
  //
  Variable = NULL;
  Status = mVariableContextIn->GetNextVariableInfo (mProtectedVariableCache, &Variable, &VarInfo);
  while (!EFI_ERROR (Status) && Variable != NULL) {
    //
    // Skip old data of the variable to be encrypted and MetaDataHmacVariable
    //
    if ((Variable->State == VAR_ADDED)
        &&
        (CompareString (VarEncInfo->Header.VariableName, VarInfo.VariableName) != 0 ||
         CompareGuid (VarEncInfo->Header.VendorGuid, VarInfo.VendorGuid) != 0)
        &&
        (CompareString (METADATA_HMAC_VARIABLE_NAME, VarInfo.VariableName) != 0 ||
         CompareGuid (METADATA_HMAC_VARIABLE_GUID, VarInfo.VendorGuid) != 0)) {
      //
      // VarX = HMAC (":" || VariableName)
      //        HMAC (":" || VendorGuid || Attributes || DataSize)
      //        HMAC (":" || CipherData)
      //        HMAC (":" || PubKeyIndex || AuthMonotonicCount || TimeStamp)
      //
      if (!UpdateVariableMetadataHmac (Context, &VarInfo, VarInfo.Data, VarInfo.DataSize)) {
        goto Done;
      }
    }

    Status = mVariableContextIn->GetNextVariableInfo (mProtectedVariableCache, &Variable, &VarInfo);
  }

  //
  // HMAC (|| NewVariable)
  //
  if (EFI_ERROR (Status) ||
      !UpdateVariableMetadataHmac (Context,
                                   &VarEncInfo->Header,
                                   VarEncInfo->CipherData,
                                   VarEncInfo->CipherDataSize)) {
    goto Done;
  }

  if (!HmacSha256Final (Context, HmacValue)) {
    ASSERT (FALSE);
    goto Done;
  }

  //
  // Force adding a new version of MetaDataHmac variable, without deleting
  // the old one.
  //
  Status = mVariableContextIn->AddVariable (
                                 METADATA_HMAC_VARIABLE_NAME,
                                 METADATA_HMAC_VARIABLE_GUID,
                                 METADATA_HMAC_VARIABLE_ATTR,
                                 HmacValue,
                                 sizeof (HmacValue)
                                 );
  ASSERT_EFI_ERROR (Status);

Done:
  if (Context != NULL) {
    FreePool (Context);
  }

  return Status;
}

EFI_STATUS
EFIAPI
ProtectedVariableLibInitialize (
  IN  PROTECTED_VARIABLE_CONTEXT_IN   *ProtectedVarLibContextIn,
  OUT PROTECTED_VARIABLE_CONTEXT_OUT  *ProtectedVarLibContextOut
  )
{
  EFI_STATUS                          Status;
  VARIABLE_STORE_HEADER               *VariableStoreHeader;
  EFI_HOB_GUID_TYPE                   *GuidHob;
  UINTN                               HobDataSize;
  PROTECTED_VARIABLE_CONTEXT_OUT      *OldContextOut;

  if (ProtectedVarLibContextIn == NULL || ProtectedVarLibContextOut == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  mVariableContextIn  = ProtectedVarLibContextIn;
  mVariableContextOut = ProtectedVarLibContextOut;

  //
  // Get root key and HMAC key from HOB created by PEI variable driver.
  //
  GuidHob = GetFirstGuidHob (&gEfiProtectedVariableKeyGuid);
  if (GuidHob == NULL) {
    ASSERT (GuidHob != NULL);
    return EFI_NOT_FOUND;
  }

  OldContextOut = GET_GUID_HOB_DATA (GuidHob);
  HobDataSize = GuidHob->Header.HobLength - sizeof (EFI_HOB_GUID_TYPE);
  if (HobDataSize < sizeof (PROTECTED_VARIABLE_CONTEXT_OUT)) {
    ASSERT (HobDataSize >= sizeof (PROTECTED_VARIABLE_CONTEXT_OUT));
    return EFI_BAD_BUFFER_SIZE;
  }
  CopyMem ((VOID *)mVariableContextOut, (CONST VOID *)OldContextOut, sizeof (*OldContextOut));

  mVariableContextOut->RootKey = AllocateRuntimeCopyPool (
                                   OldContextOut->RootKeySize,
                                   OldContextOut->RootKey
                                   );
  if (mVariableContextOut->RootKey == NULL) {
    ASSERT (mVariableContextOut->RootKey != NULL);
    return EFI_OUT_OF_RESOURCES;
  }
  ZeroMem (OldContextOut->RootKey, OldContextOut->RootKeySize);

  mVariableContextOut->MetaDataHmacKey = AllocateRuntimeCopyPool (
                                           OldContextOut->MetaDataHmacKeySize,
                                           OldContextOut->MetaDataHmacKey
                                           );
  if (mVariableContextOut->MetaDataHmacKey == NULL) {
    ASSERT (mVariableContextOut->MetaDataHmacKey != NULL);
    return EFI_OUT_OF_RESOURCES;
  }
  ZeroMem (OldContextOut->MetaDataHmacKey, OldContextOut->MetaDataHmacKeySize);

  //
  // Make sure that MetaDataHmacVariable exists.
  //
  Status = mVariableContextIn->FindVariable (
                                 METADATA_HMAC_VARIABLE_NAME,
                                 METADATA_HMAC_VARIABLE_GUID,
                                 &HmacVarInfo
                                 );
  if (EFI_ERROR (Status)) {
    ASSERT_EFI_ERROR (Status);
    return Status;
  }

  //
  // Init mProtectedVariableCache from HOB created by PEI variable driver. The
  // HOB contains data of variables which have been verified. To save memory
  // space, the blank space in varable storage was not included in the HOB.
  //
  GuidHob = GetFirstGuidHob (&gEfiProtectedVariableDataGuid);
  if (GuidHob == NULL) {
    ASSERT (GuidHob != NULL);
    return EFI_NOT_FOUND;
  }

  mProtectedVariableCache = AllocateRuntimeZeroPool (VariableStoreHeader->Size);
  if (mProtectedVariableCache == NULL) {
    ASSERT (mProtectedVariableCache != NULL);
    return EFI_OUT_OF_RESOURCES;
  }

  VariableStoreHeader = GET_GUID_HOB_DATA (GuidHob);
  VariableHobSize = GuidHob->Header.HobLength - sizeof (EFI_HOB_GUID_TYPE);
  ASSERT (VariableHobSize <= VariableStoreHeader->Size);
  CopyMem ((VOID *)mProtectedVariableCache, (CONST VOID *)VariableStoreHeader, VariableSize);

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
ProtectedVariableLibWriteInit (
  BOOLEAN                 FlushHobVariable
  )
{
  EFI_STATUS          Status;

  Status = IncrementMonotonicCounter (DEFAULT_COUNTER_INDEX);
  if (EFI_ERROR (Status)) {
    ASSERT_EFI_ERROR (Status);
    return Status;
  }

  //
  // [TODO] Flush HobVariable to flash
  //
  if (FlushHobVariable) {
    ;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
ProtectedVariableLibGetVariable (
  IN      CHAR16            *VariableName,
  IN      EFI_GUID          *VendorGuid,
  OUT     UINT32            *Attributes OPTIONAL,
  IN OUT  UINTN             *DataSize,
  OUT     VOID              *Data OPTIONAL
  )
{
  EFI_STATUS                  Status;
  VARIABLE_ENCRYPTION_INFO    VarEncInfo;
  VOID                        *PlainData;
  VARIABLE_HEADER             *Variable;
  VOID                        *DataPtr;
  UINTN                       VarOffset;
  UINTN                       DataOffset;

  SetMem (&VarEncInfo, 0, sizeof (VarEncInfo));

  //
  // Try to find the varialbe in cache first.
  //
  Status = mVariableContextIn->FindVariable (
                                 VariableName,
                                 VendorGuid,
                                 &VarEncInfo.Header
                                 );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  ASSERT ((VarOffset + sizeof (*Variable)) < mProtectedVariableCache->Size);

  //
  // The cached variable may be plain data or cipher data. Call GetCipherInfo
  // to find out.
  //
  VarEncInfo.CipherData     = VarEncInfo.Header.Data;
  VarEncInfo.CipherDataSize = VarEncInfo.Header.DataSize;
  VarEncInfo.Key            = mVariableContextOut->RootKey;
  VarEncInfo.KeySize        = mVariableContextOut->RootKeySize;

  Status = GetCipherInfo (&VarEncInfo);
  if (EFI_ERROR (Status)) {
    ASSERT_EFI_ERROR (Status);
    return Status;
  }

  //
  // Check buffer size.
  //
  if (Data == NULL && *DataSize == 0) {
    *DataSize = VarEncInfo.PlainDataSize;
    return EFI_BUFFER_TOO_SMALL;
  }

  //
  // Derypt the variable if the cached one is cipher data.
  //
  if (VarEncInfo.PlainData == NULL) {
    //
    // Overwrite the cipher data in variable cache so that we don't need to
    // do decryption next time.
    //
    VarEncInfo.DecryptInPlace = TRUE;
    Status = DecryptVariable (&VarEncInfo);
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }


  //TODO: sync cache between SMM and DXE (no need, upper layer of code will do it)

  if (Data != NULL && *DataSize > 0) {
    CopyMem (Data, VarEncInfo.PlainData, *DataSize);
  }

  if (Attributes != NULL) {
    *Attributes = VarEncInfo.Header.Attributes;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
ProtectedVariableLibSetVariable (
  IN CHAR16                  *VariableName,
  IN EFI_GUID                *VendorGuid,
  IN UINT32                  Attributes,
  IN UINTN                   DataSize,
  IN VOID                    *Data
  )
{
  VOID                              *CipherData;
  UINTN                             CipherDataSize;
  UINT32                            Counter;
  UINT8                             *Hmac;
  UINTN                             HmacSize;
  VARIABLE_ENCRYPTION_INFO          VarEncInfo;
  BOOLEAN                           AuthFlag;
  VARIABLE_POINTER_TRACK            HmacVar;
  AUTH_VARIABLE_INFO                HmacVarInfo;

  SetMem (&VarEncInfo, 0, sizeof (VarEncInfo));

  Status = mVariableContextIn->FindVariable (
                                 VariableName,
                                 VendorGuid,
                                 &VarEncInfo.Header
                                 );
  if (EFI_ERROR (Status) && Status != EFI_NOT_FOUND) {
    ASSERT_EFI_ERROR (Status);
    return Status;
  }

  if (Status == EFI_NOT_FOUND) {
    VarEncInfo.Header.VariableName  = VariableName;
    VarEncInfo.Header.VendorGuid    = VendorGuid;
    VarEncInfo.Header.Attributes    = Attributes;
    VarEncInfo.Header.TimeStamp     = &mDefaultTimeStamp;
  }
  VarEncInfo.PlainData        = Data;
  VarEncInfo.PlainDataSize    = DataSize;
  VarEncInfo.CipherData       = NULL;
  VarEncInfo.CipherDataSize   = 0;
  VarEncInfo.CipherDataType   = 0;  // Let EncryptVariable() to choose.
  VarEncInfo.Key              = mVariableContextOut->RootKey;
  VarEncInfo.KeySize          = mVariableContextOut->RootKeySize;

  Status = EncryptVariable (&VarEncInfo);
  if (EFI_ERROR (Status) ||
      VarEncInfo.CipherData == NULL ||
      VarEncInfo.CipherDataSize == 0) {
    ASSERT (FALSE);
    return Status;
  }

  //
  // Update MetaDataHmacVariable with new data of encrypted variable
  //
  Status = RefreshVariableMetadataHmac (
             VariableName,
             VendorGuid,
             Attributes,
             VarEncInfo.CipherData
             VarEncInfo.CipherDataSize,
             );
  if (EFI_ERROR (Status)) {
    goto Done;
  }

  //
  // Write encrypted variable
  //
  Status = mVariableContextIn->SetVariable (
                                 VariableName,
                                 VendorGuid,
                                 Attributes,
                                 VarEncInfo.CipherData,
                                 VarEncInfo.CipherDataSize
                                 );
  if (EFI_ERROR (Status)) {
    ASSERT_EFI_ERROR (Status);
    goto Done;
  }

  Status = IncrementMonotonicCounter (DEFAULT_COUNTER_INDEX)
  if (EFI_ERROR (Status)) {
    ASSERT_EFI_ERROR (Status);
    goto Done;
  }

  //[TODO] update MetaDataHmac variable to DELETED
  State = HmacVariable->State & VAR_DELETED
  Status = mVariableContextIn->UpdateVariableStorage (
                                 mVariableContextOut->ModuleGlobal->VariableGlobal,
                                 FALSE,
                                 FALSE,
                                 mVariableContextOut->ModuleGlobal->FvbInstance,
                                 &HmacVariable->State,
                                 sizeof (HmacVariable->State),
                                 &State
                                 );
  ASSERT_EFI_ERROR (Status);

Done:
  if (VarEncInfo.CipherData != NULL) {
    FreePool (VarEncInfo.CipherData);
  }

  return Status;
}

