/** @file
  Provides services to initialize and process authenticated variables.

Copyright (c) 2019, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _PROTECTED_VARIABLE_LIB_H_
#define _PROTECTED_VARIABLE_LIB_H_

#include <Protocol/VarCheck.h>

///
/// Size of AuthInfo prior to the data payload.
///
#define PROTECTEDINFO_SIZE ((OFFSET_OF (EFI_VARIABLE_PROTECTEDENTICATION, AuthInfo)) + \
                       (OFFSET_OF (WIN_CERTIFICATE_UEFI_GUID, CertData)) + \
                       sizeof (EFI_CERT_BLOCK_RSA_2048_SHA256))

#define PROTECTEDINFO2_SIZE(VarAuth2) ((OFFSET_OF (EFI_VARIABLE_PROTECTEDENTICATION_2, AuthInfo)) + \
                                  (UINTN) ((EFI_VARIABLE_PROTECTEDENTICATION_2 *) (VarAuth2))->AuthInfo.Hdr.dwLength)

#define OFFSET_OF_PROTECTEDINFO2_CERT_DATA ((OFFSET_OF (EFI_VARIABLE_PROTECTEDENTICATION_2, AuthInfo)) + \
                                       (OFFSET_OF (WIN_CERTIFICATE_UEFI_GUID, CertData)))

typedef struct {
  CHAR16        *VariableName;
  EFI_GUID      *VendorGuid;
  UINT32        Attributes;
  UINTN         DataSize;
  VOID          *Data;
  UINT32        PubKeyIndex;
  UINT64        MonotonicCount;
  EFI_TIME      *TimeStamp;
  VOID          *CipherData;
  UINT32        CipherDataSize;
  VOID          *Key;
  UINT32        KeyType;
  UINT32        KeySize;
} PROTECTED_VARIABLE_INFO;

/**
  Finds variable in storage blocks of volatile and non-volatile storage areas.

  This code finds variable in storage blocks of volatile and non-volatile storage areas.
  If VariableName is an empty string, then we just return the first
  qualified variable without comparing VariableName and VendorGuid.

  @param[in]  VariableName          Name of the variable to be found.
  @param[in]  VendorGuid            Variable vendor GUID to be found.
  @param[out] ProtectedVariableInfo      Pointer to PROTECTED_VARIABLE_INFO structure for
                                    output of the variable found.

  @retval EFI_INVALID_PARAMETER     If VariableName is not an empty string,
                                    while VendorGuid is NULL.
  @retval EFI_SUCCESS               Variable successfully found.
  @retval EFI_NOT_FOUND             Variable not found

**/
typedef
EFI_STATUS
(EFIAPI *PROTECTED_VAR_LIB_FIND_VARIABLE) (
  IN  CHAR16                *VariableName,
  IN  EFI_GUID              *VendorGuid,
  OUT PROTECTED_VARIABLE_INFO    *ProtectedVariableInfo
  );

/**
  Finds next variable in storage blocks of volatile and non-volatile storage areas.

  This code finds next variable in storage blocks of volatile and non-volatile storage areas.
  If VariableName is an empty string, then we just return the first
  qualified variable without comparing VariableName and VendorGuid.

  @param[in]  VariableName          Name of the variable to be found.
  @param[in]  VendorGuid            Variable vendor GUID to be found.
  @param[out] ProtectedVariableInfo      Pointer to PROTECTED_VARIABLE_INFO structure for
                                    output of the next variable.

  @retval EFI_INVALID_PARAMETER     If VariableName is not an empty string,
                                    while VendorGuid is NULL.
  @retval EFI_SUCCESS               Variable successfully found.
  @retval EFI_NOT_FOUND             Variable not found

**/
typedef
EFI_STATUS
(EFIAPI *PROTECTED_VAR_LIB_FIND_NEXT_VARIABLE) (
  IN  CHAR16                *VariableName,
  IN  EFI_GUID              *VendorGuid,
  OUT PROTECTED_VARIABLE_INFO    *ProtectedVariableInfo
  );

/**
  Update the variable region with Variable information.

  @param[in] ProtectedVariableInfo       Pointer PROTECTED_VARIABLE_INFO structure for
                                    input of the variable.

  @retval EFI_SUCCESS               The update operation is success.
  @retval EFI_INVALID_PARAMETER     Invalid parameter.
  @retval EFI_WRITE_PROTECTED       Variable is write-protected.
  @retval EFI_OUT_OF_RESOURCES      There is not enough resource.

**/
typedef
EFI_STATUS
(EFIAPI *PROTECTED_VAR_LIB_UPDATE_VARIABLE) (
  IN PROTECTED_VARIABLE_INFO     *ProtectedVariableInfo
  );

/**
  Get scratch buffer.

  @param[in, out] ScratchBufferSize Scratch buffer size. If input size is greater than
                                    the maximum supported buffer size, this value contains
                                    the maximum supported buffer size as output.
  @param[out]     ScratchBuffer     Pointer to scratch buffer address.

  @retval EFI_SUCCESS       Get scratch buffer successfully.
  @retval EFI_UNSUPPORTED   If input size is greater than the maximum supported buffer size.

**/
typedef
EFI_STATUS
(EFIAPI *PROTECTED_VAR_LIB_GET_SCRATCH_BUFFER) (
  IN OUT UINTN      *ScratchBufferSize,
  OUT    VOID       **ScratchBuffer
  );

/**
  This function is to check if the remaining variable space is enough to set
  all Variables from argument list successfully. The purpose of the check
  is to keep the consistency of the Variables to be in variable storage.

  Note: Variables are assumed to be in same storage.
  The set sequence of Variables will be same with the sequence of VariableEntry from argument list,
  so follow the argument sequence to check the Variables.

  @param[in] Attributes         Variable attributes for Variable entries.
  @param ...                    The variable argument list with type VARIABLE_ENTRY_CONSISTENCY *.
                                A NULL terminates the list. The VariableSize of
                                VARIABLE_ENTRY_CONSISTENCY is the variable data size as input.
                                It will be changed to variable total size as output.

  @retval TRUE                  Have enough variable space to set the Variables successfully.
  @retval FALSE                 No enough variable space to set the Variables successfully.

**/
typedef
BOOLEAN
(EFIAPI *PROTECTED_VAR_LIB_CHECK_REMAINING_SPACE) (
  IN UINT32                     Attributes,
  ...
  );

/**
  Return TRUE if at OS runtime.

  @retval TRUE If at OS runtime.
  @retval FALSE If at boot time.

**/
typedef
BOOLEAN
(EFIAPI *PROTECTED_VAR_LIB_AT_RUNTIME) (
  VOID
  );

/**

  This function writes data to the FWH at the correct LBA even if the LBAs
  are fragmented.

  @param Global                  Pointer to VARAIBLE_GLOBAL structure.
  @param Volatile                Point out the Variable is Volatile or Non-Volatile.
  @param SetByIndex              TRUE if target pointer is given as index.
                                 FALSE if target pointer is absolute.
  @param Fvb                     Pointer to the writable FVB protocol.
  @param DataPtrIndex            Pointer to the Data from the end of VARIABLE_STORE_HEADER
                                 structure.
  @param DataSize                Size of data to be written.
  @param Buffer                  Pointer to the buffer from which data is written.

  @retval EFI_INVALID_PARAMETER  Parameters not valid.
  @retval EFI_UNSUPPORTED        Fvb is a NULL for Non-Volatile variable update.
  @retval EFI_OUT_OF_RESOURCES   The remaining size is not enough.
  @retval EFI_SUCCESS            Variable store successfully updated.

**/
typedef
EFI_STATUS
(EFIAPI *PROTECTED_VAR_LIB_UPDATE_VARIABLE_STORAGE) (
  IN  VARIABLE_GLOBAL                     *Global,
  IN  BOOLEAN                             Volatile,
  IN  BOOLEAN                             SetByIndex,
  IN  EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL  *Fvb,
  IN  UINTN                               DataPtrIndex,
  IN  UINT32                              DataSize,
  IN  UINT8                               *Buffer
  )

#define PROTECTED_VAR_LIB_CONTEXT_IN_STRUCT_VERSION  0x01

typedef struct {
  UINTN                                       StructVersion;
  UINTN                                       StructSize;
  UINTN                                       MaxProtectedVariableSize;
  PROTECTED_VAR_LIB_FIND_VARIABLE             FindVariable;
  PROTECTED_VAR_LIB_FIND_NEXT_VARIABLE        FindNextVariable;
  PROTECTED_VAR_LIB_UPDATE_VARIABLE           UpdateVariable;
  PROTECTED_VAR_LIB_GET_SCRATCH_BUFFER        GetScratchBuffer;
  PROTECTED_VAR_LIB_CHECK_REMAINING_SPACE     CheckRemainingSpaceForConsistency;
  PROTECTED_VAR_LIB_AT_RUNTIME                AtRuntime;
  PROTECTED_VAR_LIB_UPDATE_VARIABLE_STORAGE   UpdateVariableStorage;
} PROTECTED_VAR_LIB_CONTEXT_IN;

#define PROTECTED_VAR_LIB_CONTEXT_OUT_STRUCT_VERSION 0x01

typedef struct {
  UINTN                                 StructVersion;
  UINTN                                 StructSize;
  //
  // Variable root key used to derive Encryption key and HMAC key.
  //
  UINT8                                 *RootKey;
  UINTN                                 RootKeySize;
  UINT8                                 *MetaDataHmacKey;
  UINTN                                 MetaDataHmacKeySize;
  //
  // Caller needs to ConvertPointer() for the pointers.
  //
  VOID                                  ***AddressPointer;
  UINTN                                 AddressPointerCount;
} PROTECTED_VAR_LIB_CONTEXT_OUT;

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
ProtectedVariableLibInitialize (
  IN  PROTECTED_VAR_LIB_CONTEXT_IN   *ProtectedVarLibContextIn,
  OUT PROTECTED_VAR_LIB_CONTEXT_OUT  *ProtectedVarLibContextOut
  );

EFI_STATUS
EFIAPI
ProtectedVariableLibWriteInit (
  VOID
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
ProtectedVariableLibUpdateVariableState (
  IN  CHAR16                *VariableName,
  IN  EFI_GUID              *VendorGuid,
  IN  VAR_STATE             OldState,
  IN  VAR_STATE             NewState
  );

EFI_STATUS
EFIAPI
ProtectedVariableLibAddVariable (
  IN  CHAR16                *VariableName,
  IN  EFI_GUID              *VendorGuid,
  IN UINTN                  DataSize,
  IN VOID                   *Data
  );

EFI_STATUS
EFIAPI
ProtectedVariableLibFindVariable (
  IN  CHAR16                *VariableName,
  IN  EFI_GUID              *VendorGuid,
  OUT ENC_VARIABLE_INFO     *EncVariableInfo
  );

EFI_STATUS
EFIAPI
ProtectedVariableLibFindVariableWithState (
  IN  CHAR16                *VariableName,
  IN  EFI_GUID              *VendorGuid,
  IN  VAR_STATE             State,
  OUT ENC_VARIABLE_INFO     *EncVariableInfo
  );

EFI_STATUS
EFIAPI
ProtectedVariableLibGetVariable (
  IN  CHAR16                *VariableName,
  IN  EFI_GUID              *VendorGuid,
  OUT     UINT32            *Attributes OPTIONAL,
  IN OUT  UINTN             *DataSize,
  OUT     VOID              *Data OPTIONAL
  );

EFI_STATUS
EFIAPI
ProtectedVariableLibSetVariable (
  IN CHAR16                 *VariableName,
  IN EFI_GUID               *VendorGuid,
  IN UINT32                 Attributes,
  IN UINTN                  DataSize,
  IN VOID                   *Data
  );

#endif
