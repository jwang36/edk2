/** @file
  The internal header file includes the common header files, defines
  internal structure and functions used by AuthService module.

  Caution: This module requires additional review when modified.
  This driver will have external input - variable data. It may be input in SMM mode.
  This external input must be validated carefully to avoid security issue like
  buffer overflow, integer overflow.
  Variable attribute should also be checked to avoid authentication bypass.
     The whole SMM authentication variable design relies on the integrity of flash part and SMM.
  which is assumed to be protected by platform.  All variable code and metadata in flash/SMM Memory
  may not be modified without authorization. If platform fails to protect these resources,
  the authentication service provided in this driver will be broken, and the behavior is undefined.

Copyright (c) 2009 - 2018, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _ENCRYPTION_VARIABLE_H_
#define _ENCRYPTION_VARIABLE_H_

#pragma pack(1)

typedef struct {
  UINT32     DataType;        // SYM_TYPE_AES
  UINT32     HeaderSize;      // sizeof(VARIABLE_ENCRYPTION_HEADER)
  UINT32     PlainDataSize;   // Plain data size
  UINT32     CipherDataSize;  // Cipher data size
  UINT8      KeyIvec[AES_BLOCK_SIZE];
} VARIABLE_ENCRYPTION_HEADER;

#pragma pack()

EFI_STATUS
EFIAPI
GetCipherInfo (
  IN VARIABLE_ENCRYPTION_INFO     *VarEncInfo
  );

#endif  // _ENCRYPTION_VARIABLE_H_
