/** @file
  Variable Encryption Library test application.

Copyright (c) 2019, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/EncryptionVariableLib.h>
#include <Library/BaseCryptLib.h>
#include <Library/RngLib.h>

#include <UnitTestTypes.h>
#include <Library/UnitTestLib.h>
#include <Library/UnitTestAssertLib.h>

#define UNIT_TEST_NAME        L"EncryptionVariabeLib Unit Test"
#define UNIT_TEST_VERSION     L"0.1"

#define MAX_STRING_SIZE       1025

/*******************************************************************************
TEST_VAR1 =
{
  "name"    : "TestVar1",
  "guid"    : "98E33DF3-3FFF-4FE2-B1EE-8DF5494A6B37",
  "attr"    : 0,
  "size"    : 1,
  "rootkey" : "0xC3, 0xB9, 0xD0, 0x4A, 0x16, 0xC1, 0x42, 0xDC, 0x91, 0x2C, 0x5B, 0x6C, 0xE5, 0x50, 0xA7, 0xB0,
               0x5B, 0x52, 0xD3, 0xD8, 0x75, 0x2F, 0x43, 0x36, 0x9A, 0x9D, 0xD9, 0xF3, 0xA9, 0x91, 0x3F, 0xAF",
  "ivec"    : "0xC4, 0xF6, 0xF4, 0xF6, 0x70, 0x5B, 0x46, 0xB8, 0xA5, 0x21, 0xCA, 0x97, 0xD5, 0x11, 0xEC, 0xC8",
  "data"    : "0x73",
  "cipher"  : "0x69, 0x67, 0x8D, 0xF3, 0xAE, 0x07, 0x0F, 0x4A, 0x6F, 0x5F, 0xB6, 0x5C, 0x00, 0xF9, 0xF2, 0x35"
}
**/

UINT8       mTestInitVector[] = {
  0xC4, 0xF6, 0xF4, 0xF6, 0x70, 0x5B, 0x46, 0xB8, 0xA5, 0x21, 0xCA, 0x97, 0xD5, 0x11, 0xEC, 0xC8
};

EFI_GUID    mTestVar1Guid = {
  0x98E33DF3,
  0x3FFF,
  0x4FE2,
  {0xB1, 0xEE, 0x8D, 0xF5, 0x49, 0x4A, 0x6B, 0x37}
};

UINT8       mTestVar1Data[] = {
  0x73
};

UINT8       mTestVar1CipherData[] = {
  // cipher header
  0x06, 0x00, 0x00, 0x00, // DataType
  0x20, 0x00, 0x00, 0x00, // HeaderSize
  0x01, 0x00, 0x00, 0x00, // PlainDataSize
  0x10, 0x00, 0x00, 0x00, // CipherDataSize
  0xC4, 0xF6, 0xF4, 0xF6, // IV
  0x70, 0x5B, 0x46, 0xB8,
  0xA5, 0x21, 0xCA, 0x97,
  0xD5, 0x11, 0xEC, 0xC8,
  // cipher data
  0x69, 0x67, 0x8D, 0xF3, 0xAE, 0x07, 0x0F, 0x4A, 0x6F, 0x5F, 0xB6, 0x5C, 0x00, 0xF9, 0xF2, 0x35
};

UINT8       mTestVar1RootKey[] = {
  0xC3, 0xB9, 0xD0, 0x4A, 0x16, 0xC1, 0x42, 0xDC, 0x91, 0x2C, 0x5B, 0x6C, 0xE5, 0x50, 0xA7, 0xB0,
  0x5B, 0x52, 0xD3, 0xD8, 0x75, 0x2F, 0x43, 0x36, 0x9A, 0x9D, 0xD9, 0xF3, 0xA9, 0x91, 0x3F, 0xAF
};

VARIABLE_ENCRYPTION_INFO  mTestVar1 = {
  /*Header*/            {
    /*VariableName*/      L"TestVar1",
    /*VendorGuid*/        &mTestVar1Guid,
    /*Attributes*/        0,
    /*DataSize*/          0,
    /*Data*/              NULL,
    /*PubKeyIndex*/       0,
    /*MonotonicCount*/    0,
    /*TimeStamp*/         NULL
                        },
  /*NameSize*/          16,
  /*PlainData*/         mTestVar1Data,
  /*PlainDataSize*/     1,
  /*CipherData*/        NULL,
  /*CipherDataSize*/    0,
  /*CipherHeaderSize*/  0,
  /*CipherDataType*/    0,
  /*Key*/               mTestVar1RootKey,
  /*KeySize*/           32,
  /*DecryptInPlace*/    0
};

VARIABLE_ENCRYPTION_INFO  mTestVar1_d = {
  /*Header*/            {
    /*VariableName*/      L"TestVar1",
    /*VendorGuid*/        &mTestVar1Guid,
    /*Attributes*/        0,
    /*DataSize*/          0,
    /*Data*/              NULL,
    /*PubKeyIndex*/       0,
    /*MonotonicCount*/    0,
    /*TimeStamp*/         NULL
                        },
  /*NameSize*/          16,
  /*PlainData*/         NULL,
  /*PlainDataSize*/     0,
  /*CipherData*/        mTestVar1CipherData,
  /*CipherDataSize*/    0x30,
  /*CipherHeaderSize*/  0,
  /*CipherDataType*/    0,
  /*Key*/               mTestVar1RootKey,
  /*KeySize*/           32,
  /*DecryptInPlace*/    0
};

////////////////////////////////////////////////////////////////////////////////

/*******************************************************************************
TEST_VAR2 =
{
  "name"    : "TestVar2",
  "guid"    : "1407439E-B3DC-4429-A31D-BB21819652EE",
  "attr"    : 1,
  "size"    : 8,
  "rootkey" : "0x94, 0x27, 0xAA, 0xE2, 0x15, 0xF5, 0x42, 0x49, 0xAD, 0x2A, 0x7C, 0x64, 0x14, 0xB4, 0xA1, 0x55,
               0xFF, 0x7A, 0xBB, 0x02, 0x71, 0xAA, 0x4C, 0x7A, 0x99, 0x5A, 0x75, 0xF8, 0xA3, 0xBB, 0x6C, 0x95",
  "ivec"    : "0xC4, 0xF6, 0xF4, 0xF6, 0x70, 0x5B, 0x46, 0xB8, 0xA5, 0x21, 0xCA, 0x97, 0xD5, 0x11, 0xEC, 0xC8",
  "data"    : "0x6C, 0x48, 0x0B, 0x70, 0xC6, 0x43, 0x4B, 0x80",
  "cipher"  : "0xE5, 0x3D, 0x73, 0xB3, 0x58, 0x33, 0x1D, 0x4B, 0xD6, 0x76, 0xCD, 0xC7, 0x57, 0x5C, 0xF6, 0x41"
}
**/

EFI_GUID    mTestVar2Guid = {
  0x1407439E,
  0xB3DC,
  0x4429,
  {0xA3, 0x1D, 0xBB, 0x21, 0x81, 0x96, 0x52, 0xEE}
};

UINT8       mTestVar2Data[] = {
  0x6C, 0x48, 0x0B, 0x70, 0xC6, 0x43, 0x4B, 0x80
};

UINT8       mTestVar2CipherData[] = {
  // cipher header
  0x06, 0x00, 0x00, 0x00, // DataType
  0x20, 0x00, 0x00, 0x00, // HeaderSize
  0x08, 0x00, 0x00, 0x00, // PlainDataSize
  0x10, 0x00, 0x00, 0x00, // CipherDataSize
  0xC4, 0xF6, 0xF4, 0xF6, // IV
  0x70, 0x5B, 0x46, 0xB8,
  0xA5, 0x21, 0xCA, 0x97,
  0xD5, 0x11, 0xEC, 0xC8,
  // cipher data
  0xE5, 0x3D, 0x73, 0xB3, 0x58, 0x33, 0x1D, 0x4B, 0xD6, 0x76, 0xCD, 0xC7, 0x57, 0x5C, 0xF6, 0x41
};

UINT8       mTestVar2RootKey[] = {
  0x94, 0x27, 0xAA, 0xE2, 0x15, 0xF5, 0x42, 0x49, 0xAD, 0x2A, 0x7C, 0x64, 0x14, 0xB4, 0xA1, 0x55,
  0xFF, 0x7A, 0xBB, 0x02, 0x71, 0xAA, 0x4C, 0x7A, 0x99, 0x5A, 0x75, 0xF8, 0xA3, 0xBB, 0x6C, 0x95
};

VARIABLE_ENCRYPTION_INFO  mTestVar2 = {
  /*Header*/            {
    /*VariableName*/      L"TestVar2",
    /*VendorGuid*/        &mTestVar2Guid,
    /*Attributes*/        1,
    /*DataSize*/          0,
    /*Data*/              NULL,
    /*PubKeyIndex*/       0,
    /*MonotonicCount*/    0,
    /*TimeStamp*/         NULL
                        },
  /*NameSize*/          16,
  /*PlainData*/         mTestVar2Data,
  /*PlainDataSize*/     8,
  /*CipherData*/        NULL,
  /*CipherDataSize*/    0,
  /*CipherHeaderSize*/  0,
  /*CipherDataType*/    0,
  /*Key*/               mTestVar2RootKey,
  /*KeySize*/           32,
  /*DecryptInPlace*/    0
};

VARIABLE_ENCRYPTION_INFO  mTestVar2_d = {
  /*Header*/            {
    /*VariableName*/      L"TestVar2",
    /*VendorGuid*/        &mTestVar2Guid,
    /*Attributes*/        1,
    /*DataSize*/          0,
    /*Data*/              NULL,
    /*PubKeyIndex*/       0,
    /*MonotonicCount*/    0,
    /*TimeStamp*/         NULL
                        },
  /*NameSize*/          16,
  /*PlainData*/         NULL,
  /*PlainDataSize*/     0,
  /*CipherData*/        mTestVar2CipherData,
  /*CipherDataSize*/    sizeof (mTestVar2CipherData),
  /*CipherHeaderSize*/  0,
  /*CipherDataType*/    0,
  /*Key*/               mTestVar2RootKey,
  /*KeySize*/           32,
  /*DecryptInPlace*/    0
};

////////////////////////////////////////////////////////////////////////////////

/*******************************************************************************
TEST_VAR3 =
{
  "name"    : "TestVar3",
  "guid"    : "7BAC2192-9B80-4055-BCE9-9FF05C8CFD7D",
  "attr"    : 2,
  "size"    : 15,
  "rootkey" : "0xF8, 0x30, 0xAD, 0xE8, 0x3B, 0x0E, 0x46, 0x6E, 0xBE, 0x74, 0xD0, 0xB9, 0x5B, 0x40, 0xDA, 0xC5,
               0x59, 0x80, 0xE2, 0x6F, 0xF7, 0x0F, 0x4B, 0x13, 0x86, 0x72, 0x36, 0x57, 0xE9, 0xC4, 0x77, 0x70",
  "ivec"    : "0xC4, 0xF6, 0xF4, 0xF6, 0x70, 0x5B, 0x46, 0xB8, 0xA5, 0x21, 0xCA, 0x97, 0xD5, 0x11, 0xEC, 0xC8",
  "data"    : "0x6C, 0xC9, 0x13, 0xD0, 0x9E, 0x23, 0x43, 0x1F, 0x8D, 0xEB, 0xD7, 0x34, 0x70, 0x1C, 0x3D",
  "cipher"  : "0x87, 0x5C, 0x76, 0xCE, 0xA3, 0x8A, 0xF1, 0xDD, 0x7D, 0x4E, 0xA2, 0x1D, 0x23, 0x48, 0x19, 0xA6"
}
**/

EFI_GUID    mTestVar3Guid = {
  0x7bac2192, 0x9b80, 0x4055, {0xbc, 0xe9, 0x9f, 0xf0, 0x5c, 0x8c, 0xfd, 0x7d}
};

UINT8       mTestVar3Data[] = {
  0x6C, 0xC9, 0x13, 0xD0, 0x9E, 0x23, 0x43, 0x1F, 0x8D, 0xEB, 0xD7, 0x34, 0x70, 0x1C, 0x3D
};

UINT8       mTestVar3CipherData[] = {
  // cipher header
  0x06, 0x00, 0x00, 0x00, // DataType
  0x20, 0x00, 0x00, 0x00, // HeaderSize
  0x0f, 0x00, 0x00, 0x00, // PlainDataSize
  0x10, 0x00, 0x00, 0x00, // CipherDataSize
  0xC4, 0xF6, 0xF4, 0xF6, // IV
  0x70, 0x5B, 0x46, 0xB8,
  0xA5, 0x21, 0xCA, 0x97,
  0xD5, 0x11, 0xEC, 0xC8,
  // cipher data
  0x87, 0x5C, 0x76, 0xCE, 0xA3, 0x8A, 0xF1, 0xDD, 0x7D, 0x4E, 0xA2, 0x1D, 0x23, 0x48, 0x19, 0xA6
};

UINT8       mTestVar3RootKey[] = {
  0xF8, 0x30, 0xAD, 0xE8, 0x3B, 0x0E, 0x46, 0x6E, 0xBE, 0x74, 0xD0, 0xB9, 0x5B, 0x40, 0xDA, 0xC5,
  0x59, 0x80, 0xE2, 0x6F, 0xF7, 0x0F, 0x4B, 0x13, 0x86, 0x72, 0x36, 0x57, 0xE9, 0xC4, 0x77, 0x70
};

VARIABLE_ENCRYPTION_INFO  mTestVar3 = {
  /*Header*/            {
    /*VariableName*/      L"TestVar3",
    /*VendorGuid*/        &mTestVar3Guid,
    /*Attributes*/        2,
    /*DataSize*/          0,
    /*Data*/              NULL,
    /*PubKeyIndex*/       0,
    /*MonotonicCount*/    0,
    /*TimeStamp*/         NULL
                        },
  /*NameSize*/          16,
  /*PlainData*/         mTestVar3Data,
  /*PlainDataSize*/     15,
  /*CipherData*/        NULL,
  /*CipherDataSize*/    0,
  /*CipherHeaderSize*/  0,
  /*CipherDataType*/    0,
  /*Key*/               mTestVar3RootKey,
  /*KeySize*/           32,
  /*DecryptInPlace*/    0
};

VARIABLE_ENCRYPTION_INFO  mTestVar3_d = {
  /*Header*/            {
    /*VariableName*/      L"TestVar3",
    /*VendorGuid*/        &mTestVar3Guid,
    /*Attributes*/        2,
    /*DataSize*/          0,
    /*Data*/              NULL,
    /*PubKeyIndex*/       0,
    /*MonotonicCount*/    0,
    /*TimeStamp*/         NULL
                        },
  /*NameSize*/          16,
  /*PlainData*/         NULL,
  /*PlainDataSize*/     0,
  /*CipherData*/        mTestVar3CipherData,
  /*CipherDataSize*/    sizeof (mTestVar3CipherData),
  /*CipherHeaderSize*/  0,
  /*CipherDataType*/    0,
  /*Key*/               mTestVar3RootKey,
  /*KeySize*/           32,
  /*DecryptInPlace*/    0
};

////////////////////////////////////////////////////////////////////////////////

/*******************************************************************************
TEST_VAR4 =
{
  "name"    : "TestVar4",
  "guid"    : "23506D66-9F40-4BE8-9592-A61EC105E2B1",
  "attr"    : 3,
  "size"    : 16,
  "rootkey" : "0x7B, 0x5C, 0xE7, 0x49, 0xD9, 0x4D, 0x44, 0x6B, 0xBA, 0x91, 0xC8, 0x0F, 0x14, 0x8C, 0xE2, 0xF8,
               0x46, 0xBF, 0x65, 0xC5, 0x0A, 0x9E, 0x4B, 0xDC, 0x9C, 0x47, 0xB6, 0x8A, 0x0E, 0x2A, 0xDE, 0x51",
  "ivec"    : "0xC4, 0xF6, 0xF4, 0xF6, 0x70, 0x5B, 0x46, 0xB8, 0xA5, 0x21, 0xCA, 0x97, 0xD5, 0x11, 0xEC, 0xC8",
  "data"    : "0x68, 0x67, 0xAD, 0x9C, 0x76, 0x66, 0x47, 0xA2, 0x95, 0xD8, 0x53, 0xC2, 0x12, 0x4E, 0xD3, 0xA8",
  "cipher"  : "0xF1, 0x88, 0xF0, 0xBE, 0x20, 0xFD, 0x07, 0xA1, 0x69, 0x84, 0xDD, 0xAC, 0xB9, 0x75, 0x3B, 0x8A"
}
*******************************************************************************/

EFI_GUID    mTestVar4Guid = {
  0x23506d66, 0x9f40, 0x4be8, {0x95, 0x92, 0xa6, 0x1e, 0xc1, 0x05, 0xe2, 0xb1}
};

UINT8       mTestVar4Data[] = {
  0x68, 0x67, 0xAD, 0x9C, 0x76, 0x66, 0x47, 0xA2, 0x95, 0xD8, 0x53, 0xC2, 0x12, 0x4E, 0xD3, 0xA8
};

UINT8       mTestVar4CipherData[] = {
  // cipher header
  0x06, 0x00, 0x00, 0x00, // DataType
  0x20, 0x00, 0x00, 0x00, // HeaderSize
  0x10, 0x00, 0x00, 0x00, // PlainDataSize
  0x10, 0x00, 0x00, 0x00, // CipherDataSize
  0xC4, 0xF6, 0xF4, 0xF6, // IV
  0x70, 0x5B, 0x46, 0xB8,
  0xA5, 0x21, 0xCA, 0x97,
  0xD5, 0x11, 0xEC, 0xC8,
  // cipher data
  0xF1, 0x88, 0xF0, 0xBE, 0x20, 0xFD, 0x07, 0xA1, 0x69, 0x84, 0xDD, 0xAC, 0xB9, 0x75, 0x3B, 0x8A
};

UINT8       mTestVar4RootKey[] = {
  0x7B, 0x5C, 0xE7, 0x49, 0xD9, 0x4D, 0x44, 0x6B, 0xBA, 0x91, 0xC8, 0x0F, 0x14, 0x8C, 0xE2, 0xF8,
  0x46, 0xBF, 0x65, 0xC5, 0x0A, 0x9E, 0x4B, 0xDC, 0x9C, 0x47, 0xB6, 0x8A, 0x0E, 0x2A, 0xDE, 0x51
};

VARIABLE_ENCRYPTION_INFO  mTestVar4 = {
  /*Header*/            {
    /*VariableName*/      L"TestVar4",
    /*VendorGuid*/        &mTestVar4Guid,
    /*Attributes*/        3,
    /*DataSize*/          0,
    /*Data*/              NULL,
    /*PubKeyIndex*/       0,
    /*MonotonicCount*/    0,
    /*TimeStamp*/         NULL
                        },
  /*NameSize*/          16,
  /*PlainData*/         mTestVar4Data,
  /*PlainDataSize*/     16,
  /*CipherData*/        NULL,
  /*CipherDataSize*/    0,
  /*CipherHeaderSize*/  0,
  /*CipherDataType*/    0,
  /*Key*/               mTestVar4RootKey,
  /*KeySize*/           32,
  /*DecryptInPlace*/    0
};

VARIABLE_ENCRYPTION_INFO  mTestVar4_d = {
  /*Header*/            {
    /*VariableName*/      L"TestVar4",
    /*VendorGuid*/        &mTestVar4Guid,
    /*Attributes*/        3,
    /*DataSize*/          0,
    /*Data*/              NULL,
    /*PubKeyIndex*/       0,
    /*MonotonicCount*/    0,
    /*TimeStamp*/         NULL
                        },
  /*NameSize*/          16,
  /*PlainData*/         NULL,
  /*PlainDataSize*/     0,
  /*CipherData*/        mTestVar4CipherData,
  /*CipherDataSize*/    sizeof (mTestVar4CipherData),
  /*CipherHeaderSize*/  0,
  /*CipherDataType*/    0,
  /*Key*/               mTestVar4RootKey,
  /*KeySize*/           32,
  /*DecryptInPlace*/    0
};

////////////////////////////////////////////////////////////////////////////////

/*******************************************************************************
TEST_VAR5 =
{
  "name"    : "TestVar5",
  "guid"    : "752984F1-9E96-453A-B028-DFB7847056F1",
  "attr"    : 4,
  "size"    : 18,
  "rootkey" : "0xE6, 0xF7, 0x98, 0x05, 0x5D, 0xB0, 0x46, 0x90, 0xA3, 0xEB, 0xD2, 0xA1, 0x96, 0x1B, 0x24, 0x0A,
               0x77, 0x7C, 0x60, 0xC5, 0xA0, 0x21, 0x43, 0x91, 0xBE, 0xE9, 0x9A, 0xFA, 0xA4, 0x60, 0x69, 0x9A",
  "ivec"    : "0xC4, 0xF6, 0xF4, 0xF6, 0x70, 0x5B, 0x46, 0xB8, 0xA5, 0x21, 0xCA, 0x97, 0xD5, 0x11, 0xEC, 0xC8",
  "data"    : "0xA4, 0xE2, 0x5D, 0xB5, 0x7D, 0x6D, 0x4E, 0x87, 0xB6, 0x6B, 0x44, 0xC3, 0xB0, 0xF6, 0x48, 0x59,
               0x2C, 0x39",
  "cipher"  : "0x82, 0x93, 0xBC, 0xCA, 0x0A, 0xEA, 0x40, 0x41, 0x20, 0xFD, 0x9F, 0x6B, 0xCC, 0x91, 0xCD, 0x7F,
               0xC3, 0x3F, 0x41, 0x9E, 0x6F, 0x97, 0x8E, 0xCD, 0xC1, 0x09, 0x5B, 0x0A, 0x6D, 0x22, 0x03, 0x2C"
}
*******************************************************************************/
EFI_GUID    mTestVar5Guid = {
  0x752984f1, 0x9e96, 0x453a, {0xb0, 0x28, 0xdf, 0xb7, 0x84, 0x70, 0x56, 0xf1}
};

UINT8       mTestVar5Data[] = {
  0xA4, 0xE2, 0x5D, 0xB5, 0x7D, 0x6D, 0x4E, 0x87, 0xB6, 0x6B, 0x44, 0xC3, 0xB0, 0xF6, 0x48, 0x59,
  0x2C, 0x39
};

UINT8       mTestVar5CipherData[] = {
  // cipher header
  0x06, 0x00, 0x00, 0x00, // DataType
  0x20, 0x00, 0x00, 0x00, // HeaderSize
  0x12, 0x00, 0x00, 0x00, // PlainDataSize
  0x20, 0x00, 0x00, 0x00, // CipherDataSize
  0xC4, 0xF6, 0xF4, 0xF6, // IV
  0x70, 0x5B, 0x46, 0xB8,
  0xA5, 0x21, 0xCA, 0x97,
  0xD5, 0x11, 0xEC, 0xC8,
  // cipher data
  0x82, 0x93, 0xBC, 0xCA, 0x0A, 0xEA, 0x40, 0x41, 0x20, 0xFD, 0x9F, 0x6B, 0xCC, 0x91, 0xCD, 0x7F,
  0xC3, 0x3F, 0x41, 0x9E, 0x6F, 0x97, 0x8E, 0xCD, 0xC1, 0x09, 0x5B, 0x0A, 0x6D, 0x22, 0x03, 0x2C
};

UINT8       mTestVar5RootKey[] = {
  0xE6, 0xF7, 0x98, 0x05, 0x5D, 0xB0, 0x46, 0x90, 0xA3, 0xEB, 0xD2, 0xA1, 0x96, 0x1B, 0x24, 0x0A,
  0x77, 0x7C, 0x60, 0xC5, 0xA0, 0x21, 0x43, 0x91, 0xBE, 0xE9, 0x9A, 0xFA, 0xA4, 0x60, 0x69, 0x9A
};

VARIABLE_ENCRYPTION_INFO  mTestVar5 = {
  /*Header*/            {
    /*VariableName*/      L"TestVar5",
    /*VendorGuid*/        &mTestVar5Guid,
    /*Attributes*/        4,
    /*DataSize*/          0,
    /*Data*/              NULL,
    /*PubKeyIndex*/       0,
    /*MonotonicCount*/    0,
    /*TimeStamp*/         NULL
                        },
  /*NameSize*/          16,
  /*PlainData*/         mTestVar5Data,
  /*PlainDataSize*/     18,
  /*CipherData*/        NULL,
  /*CipherDataSize*/    0,
  /*CipherHeaderSize*/  0,
  /*CipherDataType*/    0,
  /*Key*/               mTestVar5RootKey,
  /*KeySize*/           32,
  /*DecryptInPlace*/    0
};

VARIABLE_ENCRYPTION_INFO  mTestVar5_d = {
  /*Header*/            {
    /*VariableName*/      L"TestVar5",
    /*VendorGuid*/        &mTestVar5Guid,
    /*Attributes*/        4,
    /*DataSize*/          0,
    /*Data*/              NULL,
    /*PubKeyIndex*/       0,
    /*MonotonicCount*/    0,
    /*TimeStamp*/         NULL
                        },
  /*NameSize*/          16,
  /*PlainData*/         NULL,
  /*PlainDataSize*/     0,
  /*CipherData*/        mTestVar5CipherData,
  /*CipherDataSize*/    sizeof (mTestVar5CipherData),
  /*CipherHeaderSize*/  0,
  /*CipherDataType*/    0,
  /*Key*/               mTestVar5RootKey,
  /*KeySize*/           32,
  /*DecryptInPlace*/    0
};

////////////////////////////////////////////////////////////////////////////////

/*******************************************************************************
TEST_VAR6 =
{
  "name"    : "TestVar6",
  "guid"    : "F10EF59D-3825-4561-894D-677AB6C493DA",
  "attr"    : 5,
  "size"    : 32,
  "rootkey" : "0x81, 0x3C, 0x44, 0x90, 0xCE, 0xCC, 0x46, 0x1B, 0x9E, 0x5A, 0x87, 0x8C, 0x7B, 0x0C, 0xCF, 0x4A,
               0x3A, 0xAA, 0x4B, 0xB8, 0x69, 0xBA, 0x46, 0x8D, 0x88, 0x62, 0x30, 0x36, 0xE1, 0xDA, 0xD4, 0xD7",
  "ivec"    : "0xC4, 0xF6, 0xF4, 0xF6, 0x70, 0x5B, 0x46, 0xB8, 0xA5, 0x21, 0xCA, 0x97, 0xD5, 0x11, 0xEC, 0xC8",
  "data"    : "0xAE, 0x66, 0xC2, 0x62, 0xF7, 0x24, 0x4A, 0x8C, 0xA8, 0x74, 0x05, 0x52, 0x8C, 0x0C, 0xF5, 0xFE,
               0xA7, 0x0C, 0x74, 0xAD, 0x36, 0xA6, 0x43, 0x0B, 0xA6, 0x61, 0x1B, 0x96, 0xF4, 0xFF, 0xEF, 0x94",
  "cipher"  : "0xDB, 0x14, 0x86, 0x6A, 0x0F, 0xDF, 0x27, 0x89, 0xDB, 0x1C, 0xC2, 0xF2, 0xCF, 0xE4, 0xE4, 0x0A,
               0x0A, 0xA7, 0xC1, 0xAF, 0x60, 0x78, 0x39, 0x5D, 0x17, 0x56, 0xEB, 0x52, 0x9D, 0xE2, 0x08, 0xC2"
}
*******************************************************************************/
EFI_GUID    mTestVar6Guid = {
  0xf10ef59d, 0x3825, 0x4561, {0x89, 0x4d, 0x67, 0x7a, 0xb6, 0xc4, 0x93, 0xda}
};

UINT8       mTestVar6Data[] = {
  0xAE, 0x66, 0xC2, 0x62, 0xF7, 0x24, 0x4A, 0x8C, 0xA8, 0x74, 0x05, 0x52, 0x8C, 0x0C, 0xF5, 0xFE,
  0xA7, 0x0C, 0x74, 0xAD, 0x36, 0xA6, 0x43, 0x0B, 0xA6, 0x61, 0x1B, 0x96, 0xF4, 0xFF, 0xEF, 0x94
};

UINT8       mTestVar6CipherData[] = {
  // cipher header
  0x06, 0x00, 0x00, 0x00, // DataType
  0x20, 0x00, 0x00, 0x00, // HeaderSize
  0x20, 0x00, 0x00, 0x00, // PlainDataSize
  0x20, 0x00, 0x00, 0x00, // CipherDataSize
  0xC4, 0xF6, 0xF4, 0xF6, // IV
  0x70, 0x5B, 0x46, 0xB8,
  0xA5, 0x21, 0xCA, 0x97,
  0xD5, 0x11, 0xEC, 0xC8,
  // cipher data
  0xDB, 0x14, 0x86, 0x6A, 0x0F, 0xDF, 0x27, 0x89, 0xDB, 0x1C, 0xC2, 0xF2, 0xCF, 0xE4, 0xE4, 0x0A,
  0x0A, 0xA7, 0xC1, 0xAF, 0x60, 0x78, 0x39, 0x5D, 0x17, 0x56, 0xEB, 0x52, 0x9D, 0xE2, 0x08, 0xC2
};

UINT8       mTestVar6RootKey[] = {
  0x81, 0x3C, 0x44, 0x90, 0xCE, 0xCC, 0x46, 0x1B, 0x9E, 0x5A, 0x87, 0x8C, 0x7B, 0x0C, 0xCF, 0x4A,
  0x3A, 0xAA, 0x4B, 0xB8, 0x69, 0xBA, 0x46, 0x8D, 0x88, 0x62, 0x30, 0x36, 0xE1, 0xDA, 0xD4, 0xD7
};

VARIABLE_ENCRYPTION_INFO  mTestVar6 = {
  /*Header*/            {
    /*VariableName*/      L"TestVar6",
    /*VendorGuid*/        &mTestVar6Guid,
    /*Attributes*/        5,
    /*DataSize*/          0,
    /*Data*/              NULL,
    /*PubKeyIndex*/       0,
    /*MonotonicCount*/    0,
    /*TimeStamp*/         NULL
                        },
  /*NameSize*/          16,
  /*PlainData*/         mTestVar6Data,
  /*PlainDataSize*/     32,
  /*CipherData*/        NULL,
  /*CipherDataSize*/    0,
  /*CipherHeaderSize*/  0,
  /*CipherDataType*/    0,
  /*Key*/               mTestVar6RootKey,
  /*KeySize*/           32,
  /*DecryptInPlace*/    0
};

VARIABLE_ENCRYPTION_INFO  mTestVar6_d = {
  /*Header*/            {
    /*VariableName*/      L"TestVar6",
    /*VendorGuid*/        &mTestVar6Guid,
    /*Attributes*/        5,
    /*DataSize*/          0,
    /*Data*/              NULL,
    /*PubKeyIndex*/       0,
    /*MonotonicCount*/    0,
    /*TimeStamp*/         NULL
                        },
  /*NameSize*/          16,
  /*PlainData*/         NULL,
  /*PlainDataSize*/     0,
  /*CipherData*/        mTestVar6CipherData,
  /*CipherDataSize*/    sizeof (mTestVar6CipherData),
  /*CipherHeaderSize*/  0,
  /*CipherDataType*/    0,
  /*Key*/               mTestVar6RootKey,
  /*KeySize*/           32,
  /*DecryptInPlace*/    0
};

////////////////////////////////////////////////////////////////////////////////

/*******************************************************************************
TEST_VAR7 =
{
  "name"    : "TestVar7",
  "guid"    : "903EF4CE-055B-45B5-A781-EB49C35CE2B5",
  "attr"    : 6,
  "size"    : 33,
  "rootkey" : "0x9B, 0xC8, 0x4A, 0xDA, 0x33, 0x7C, 0x4C, 0x96, 0x90, 0x6B, 0xD2, 0xFD, 0xBD, 0xC2, 0x46, 0x4D,
               0x4E, 0x65, 0xE4, 0x96, 0x02, 0x6B, 0x41, 0xB4, 0x8B, 0x49, 0x63, 0x0C, 0xF3, 0x7E, 0x37, 0xDA",
  "ivec"    : "0xC4, 0xF6, 0xF4, 0xF6, 0x70, 0x5B, 0x46, 0xB8, 0xA5, 0x21, 0xCA, 0x97, 0xD5, 0x11, 0xEC, 0xC8",
  "data"    : "0xCA, 0x8A, 0x42, 0x22, 0x69, 0xDC, 0x42, 0x62, 0x85, 0xD8, 0xBF, 0xDE, 0x12, 0x06, 0x31, 0x67,
               0x17, 0x60, 0x4C, 0x04, 0x88, 0xE7, 0x4D, 0xF5, 0x89, 0x4A, 0xAC, 0x53, 0xF5, 0x6E, 0x86, 0xB7,
               0x3A",
  "cipher"  : "0xC4, 0xF3, 0x69, 0x3A, 0x0D, 0xC0, 0x31, 0xFF, 0x15, 0x08, 0xFB, 0x44, 0xCE, 0xCE, 0x93, 0xD4,
               0xF1, 0xD9, 0xDA, 0xEE, 0x51, 0xDF, 0x0A, 0xE1, 0xBB, 0xD5, 0x8F, 0x88, 0x27, 0x0C, 0xBA, 0xDE,
               0x60, 0xE8, 0x48, 0x42, 0xF6, 0xC2, 0xD9, 0x81, 0x82, 0x9D, 0x2C, 0xCF, 0x0F, 0x20, 0x83, 0x46"
}
*******************************************************************************/

EFI_GUID    mTestVar7Guid = {
  0x903ef4ce, 0x055b, 0x45b5, {0xa7, 0x81, 0xeb, 0x49, 0xc3, 0x5c, 0xe2, 0xb5}
};

UINT8       mTestVar7Data[] = {
  0xCA, 0x8A, 0x42, 0x22, 0x69, 0xDC, 0x42, 0x62, 0x85, 0xD8, 0xBF, 0xDE, 0x12, 0x06, 0x31, 0x67,
  0x17, 0x60, 0x4C, 0x04, 0x88, 0xE7, 0x4D, 0xF5, 0x89, 0x4A, 0xAC, 0x53, 0xF5, 0x6E, 0x86, 0xB7,
  0x3A
};

UINT8       mTestVar7CipherData[] = {
  // cipher header
  0x06, 0x00, 0x00, 0x00, // DataType
  0x20, 0x00, 0x00, 0x00, // HeaderSize
  0x21, 0x00, 0x00, 0x00, // PlainDataSize
  0x30, 0x00, 0x00, 0x00, // CipherDataSize
  0xC4, 0xF6, 0xF4, 0xF6, // IV
  0x70, 0x5B, 0x46, 0xB8,
  0xA5, 0x21, 0xCA, 0x97,
  0xD5, 0x11, 0xEC, 0xC8,
  // cipher data
  0xC4, 0xF3, 0x69, 0x3A, 0x0D, 0xC0, 0x31, 0xFF, 0x15, 0x08, 0xFB, 0x44, 0xCE, 0xCE, 0x93, 0xD4,
  0xF1, 0xD9, 0xDA, 0xEE, 0x51, 0xDF, 0x0A, 0xE1, 0xBB, 0xD5, 0x8F, 0x88, 0x27, 0x0C, 0xBA, 0xDE,
  0x60, 0xE8, 0x48, 0x42, 0xF6, 0xC2, 0xD9, 0x81, 0x82, 0x9D, 0x2C, 0xCF, 0x0F, 0x20, 0x83, 0x46
};

UINT8       mTestVar7RootKey[] = {
  0x9B, 0xC8, 0x4A, 0xDA, 0x33, 0x7C, 0x4C, 0x96, 0x90, 0x6B, 0xD2, 0xFD, 0xBD, 0xC2, 0x46, 0x4D,
  0x4E, 0x65, 0xE4, 0x96, 0x02, 0x6B, 0x41, 0xB4, 0x8B, 0x49, 0x63, 0x0C, 0xF3, 0x7E, 0x37, 0xDA
};

VARIABLE_ENCRYPTION_INFO  mTestVar7 = {
  /*Header*/            {
    /*VariableName*/      L"TestVar7",
    /*VendorGuid*/        &mTestVar7Guid,
    /*Attributes*/        6,
    /*DataSize*/          0,
    /*Data*/              NULL,
    /*PubKeyIndex*/       0,
    /*MonotonicCount*/    0,
    /*TimeStamp*/         NULL
                        },
  /*NameSize*/          16,
  /*PlainData*/         mTestVar7Data,
  /*PlainDataSize*/     33,
  /*CipherData*/        NULL,
  /*CipherDataSize*/    0,
  /*CipherHeaderSize*/  0,
  /*CipherDataType*/    0,
  /*Key*/               mTestVar7RootKey,
  /*KeySize*/           32,
  /*DecryptInPlace*/    0
};

VARIABLE_ENCRYPTION_INFO  mTestVar7_d = {
  /*Header*/            {
    /*VariableName*/      L"TestVar7",
    /*VendorGuid*/        &mTestVar7Guid,
    /*Attributes*/        6,
    /*DataSize*/          0,
    /*Data*/              NULL,
    /*PubKeyIndex*/       0,
    /*MonotonicCount*/    0,
    /*TimeStamp*/         NULL
                        },
  /*NameSize*/          16,
  /*PlainData*/         NULL,
  /*PlainDataSize*/     0,
  /*CipherData*/        mTestVar7CipherData,
  /*CipherDataSize*/    sizeof (mTestVar7CipherData),
  /*CipherHeaderSize*/  0,
  /*CipherDataType*/    0,
  /*Key*/               mTestVar7RootKey,
  /*KeySize*/           32,
  /*DecryptInPlace*/    0
};

////////////////////////////////////////////////////////////////////////////////


BOOLEAN
EFIAPI
GetRandomNumber64 (
  OUT     UINT64                    *Rand
  )
{
  ASSERT (FALSE);
  return FALSE;
}

BOOLEAN
EFIAPI
GetRandomNumber128 (
  OUT     UINT64                    *Rand
  )
{
  CopyMem (Rand, mTestInitVector, 128/8);
  return TRUE;
}

UNIT_TEST_STATUS
EFIAPI
TestEncryptVariableSetup (
  UNIT_TEST_FRAMEWORK_HANDLE  Framework,
  UNIT_TEST_CONTEXT           Context
  )
{
  return UNIT_TEST_PASSED;
}

UNIT_TEST_STATUS
EFIAPI
TestEncryptVariableTearDown (
  UNIT_TEST_FRAMEWORK_HANDLE  Framework,
  UNIT_TEST_CONTEXT           Context
  )
{
  return UNIT_TEST_PASSED;
}

UNIT_TEST_STATUS
EFIAPI
TestVariableEncryption (
  IN UNIT_TEST_FRAMEWORK_HANDLE  Framework,
  IN UNIT_TEST_CONTEXT           Context
  )
{
  EFI_STATUS                Status;
  VARIABLE_ENCRYPTION_INFO  *VarEncInfo;

  VarEncInfo = &mTestVar1;
  Status = EncryptVariable (VarEncInfo);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataType, 6);
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataSize, sizeof(mTestVar1CipherData));
  UT_ASSERT_MEM_EQUAL (VarEncInfo->CipherData, mTestVar1CipherData, sizeof(mTestVar1CipherData));

  VarEncInfo = &mTestVar2;
  Status = EncryptVariable (VarEncInfo);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataType, 6);
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataSize, sizeof(mTestVar2CipherData));
  UT_ASSERT_MEM_EQUAL (VarEncInfo->CipherData, mTestVar2CipherData, sizeof(mTestVar2CipherData));

  VarEncInfo = &mTestVar3;
  Status = EncryptVariable (VarEncInfo);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataType, 6);
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataSize, sizeof(mTestVar3CipherData));
  UT_ASSERT_MEM_EQUAL (VarEncInfo->CipherData, mTestVar3CipherData, sizeof(mTestVar3CipherData));

  VarEncInfo = &mTestVar4;
  Status = EncryptVariable (VarEncInfo);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataType, 6);
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataSize, sizeof(mTestVar4CipherData));
  UT_ASSERT_MEM_EQUAL (VarEncInfo->CipherData, mTestVar4CipherData, sizeof(mTestVar4CipherData));

  VarEncInfo = &mTestVar5;
  Status = EncryptVariable (VarEncInfo);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataType, 6);
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataSize, sizeof(mTestVar5CipherData));
  UT_ASSERT_MEM_EQUAL (VarEncInfo->CipherData, mTestVar5CipherData, sizeof(mTestVar5CipherData));

  VarEncInfo = &mTestVar6;
  Status = EncryptVariable (VarEncInfo);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataType, 6);
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataSize, sizeof(mTestVar6CipherData));
  UT_ASSERT_MEM_EQUAL (VarEncInfo->CipherData, mTestVar6CipherData, sizeof(mTestVar6CipherData));

  VarEncInfo = &mTestVar7;
  Status = EncryptVariable (VarEncInfo);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataType, 6);
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataSize, sizeof(mTestVar7CipherData));
  UT_ASSERT_MEM_EQUAL (VarEncInfo->CipherData, mTestVar7CipherData, sizeof(mTestVar7CipherData));

  return UNIT_TEST_PASSED;
}

UNIT_TEST_STATUS
EFIAPI
TestVariableDecryption (
  IN UNIT_TEST_FRAMEWORK_HANDLE  Framework,
  IN UNIT_TEST_CONTEXT           Context
  )
{
  EFI_STATUS                Status;
  VARIABLE_ENCRYPTION_INFO  *VarEncInfo;

  VarEncInfo = &mTestVar1_d;
  Status = DecryptVariable (VarEncInfo);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataType, 6);
  UT_ASSERT_EQUAL (VarEncInfo->CipherHeaderSize, 0x20);
  UT_ASSERT_EQUAL (VarEncInfo->PlainDataSize, sizeof (mTestVar1Data));
  UT_ASSERT_MEM_EQUAL (VarEncInfo->PlainData, mTestVar1Data, VarEncInfo->PlainDataSize);

  VarEncInfo = &mTestVar2_d;
  Status = DecryptVariable (VarEncInfo);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataType, 6);
  UT_ASSERT_EQUAL (VarEncInfo->CipherHeaderSize, 0x20);
  UT_ASSERT_EQUAL (VarEncInfo->PlainDataSize, sizeof (mTestVar2Data));
  UT_ASSERT_MEM_EQUAL (VarEncInfo->PlainData, mTestVar2Data, VarEncInfo->PlainDataSize);

  VarEncInfo = &mTestVar3_d;
  Status = DecryptVariable (VarEncInfo);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataType, 6);
  UT_ASSERT_EQUAL (VarEncInfo->CipherHeaderSize, 0x20);
  UT_ASSERT_EQUAL (VarEncInfo->PlainDataSize, sizeof (mTestVar3Data));
  UT_ASSERT_MEM_EQUAL (VarEncInfo->PlainData, mTestVar3Data, VarEncInfo->PlainDataSize);

  VarEncInfo = &mTestVar4_d;
  Status = DecryptVariable (VarEncInfo);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataType, 6);
  UT_ASSERT_EQUAL (VarEncInfo->CipherHeaderSize, 0x20);
  UT_ASSERT_EQUAL (VarEncInfo->PlainDataSize, sizeof (mTestVar4Data));
  UT_ASSERT_MEM_EQUAL (VarEncInfo->PlainData, mTestVar4Data, VarEncInfo->PlainDataSize);

  VarEncInfo = &mTestVar5_d;
  Status = DecryptVariable (VarEncInfo);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataType, 6);
  UT_ASSERT_EQUAL (VarEncInfo->CipherHeaderSize, 0x20);
  UT_ASSERT_EQUAL (VarEncInfo->PlainDataSize, sizeof (mTestVar5Data));
  UT_ASSERT_MEM_EQUAL (VarEncInfo->PlainData, mTestVar5Data, VarEncInfo->PlainDataSize);

  VarEncInfo = &mTestVar6_d;
  Status = DecryptVariable (VarEncInfo);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataType, 6);
  UT_ASSERT_EQUAL (VarEncInfo->CipherHeaderSize, 0x20);
  UT_ASSERT_EQUAL (VarEncInfo->PlainDataSize, sizeof (mTestVar6Data));
  UT_ASSERT_MEM_EQUAL (VarEncInfo->PlainData, mTestVar6Data, VarEncInfo->PlainDataSize);

  VarEncInfo = &mTestVar7_d;
  Status = DecryptVariable (VarEncInfo);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataType, 6);
  UT_ASSERT_EQUAL (VarEncInfo->CipherHeaderSize, 0x20);
  UT_ASSERT_EQUAL (VarEncInfo->PlainDataSize, sizeof (mTestVar7Data));
  UT_ASSERT_MEM_EQUAL (VarEncInfo->PlainData, mTestVar7Data, VarEncInfo->PlainDataSize);

  return UNIT_TEST_PASSED;
}

UNIT_TEST_STATUS
EFIAPI
TestGetCipherInfo (
  IN UNIT_TEST_FRAMEWORK_HANDLE  Framework,
  IN UNIT_TEST_CONTEXT           Context
  )
{
  EFI_STATUS                Status;
  VARIABLE_ENCRYPTION_INFO  *VarEncInfo;

  //
  // TestVar1
  //
  VarEncInfo = &mTestVar1_d;

  Status = GetCipherInfo (VarEncInfo);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);
  UT_ASSERT_EQUAL (VarEncInfo->PlainDataSize, sizeof (mTestVar1Data));
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataType, 6);
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataSize, sizeof (mTestVar1CipherData));
  UT_ASSERT_EQUAL (VarEncInfo->CipherHeaderSize, 0x20);

  VarEncInfo->DecryptInPlace = TRUE;
  Status = DecryptVariable (VarEncInfo);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataType, 6);
  UT_ASSERT_EQUAL (VarEncInfo->CipherHeaderSize, 0x20);
  UT_ASSERT_EQUAL (VarEncInfo->PlainDataSize, sizeof (mTestVar1Data));
  UT_ASSERT_MEM_EQUAL (VarEncInfo->PlainData, mTestVar1Data, VarEncInfo->PlainDataSize);
  UT_ASSERT_MEM_EQUAL (mTestVar1CipherData + 0x20, mTestVar1Data, VarEncInfo->PlainDataSize);

  VarEncInfo->PlainData = NULL;
  VarEncInfo->PlainDataSize = 0;
  Status = GetCipherInfo (VarEncInfo);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);
  UT_ASSERT_EQUAL (VarEncInfo->PlainDataSize, sizeof (mTestVar1Data));
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataType, 0);
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataSize, 0);
  UT_ASSERT_EQUAL (VarEncInfo->CipherHeaderSize, 0x20);
  UT_ASSERT_NOT_NULL (VarEncInfo->PlainData);
  UT_ASSERT_MEM_EQUAL (VarEncInfo->PlainData, mTestVar1Data, VarEncInfo->PlainDataSize);

  //
  // TestVar2
  //
  VarEncInfo = &mTestVar2_d;

  Status = GetCipherInfo (VarEncInfo);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);
  UT_ASSERT_EQUAL (VarEncInfo->PlainDataSize, sizeof (mTestVar2Data));
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataType, 6);
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataSize, sizeof (mTestVar2CipherData));
  UT_ASSERT_EQUAL (VarEncInfo->CipherHeaderSize, 0x20);

  VarEncInfo->DecryptInPlace = TRUE;
  Status = DecryptVariable (VarEncInfo);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataType, 6);
  UT_ASSERT_EQUAL (VarEncInfo->CipherHeaderSize, 0x20);
  UT_ASSERT_EQUAL (VarEncInfo->PlainDataSize, sizeof (mTestVar2Data));
  UT_ASSERT_MEM_EQUAL (VarEncInfo->PlainData, mTestVar2Data, VarEncInfo->PlainDataSize);
  UT_ASSERT_MEM_EQUAL (mTestVar2CipherData + 0x20, mTestVar2Data, VarEncInfo->PlainDataSize);

  VarEncInfo->PlainData = NULL;
  VarEncInfo->PlainDataSize = 0;
  Status = GetCipherInfo (VarEncInfo);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);
  UT_ASSERT_EQUAL (VarEncInfo->PlainDataSize, sizeof (mTestVar2Data));
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataType, 0);
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataSize, 0);
  UT_ASSERT_EQUAL (VarEncInfo->CipherHeaderSize, 0x20);
  UT_ASSERT_NOT_NULL (VarEncInfo->PlainData);
  UT_ASSERT_MEM_EQUAL (VarEncInfo->PlainData, mTestVar2Data, VarEncInfo->PlainDataSize);

  //
  // TestVar3
  //
  VarEncInfo = &mTestVar3_d;

  Status = GetCipherInfo (VarEncInfo);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);
  UT_ASSERT_EQUAL (VarEncInfo->PlainDataSize, sizeof (mTestVar3Data));
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataType, 6);
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataSize, sizeof (mTestVar3CipherData));
  UT_ASSERT_EQUAL (VarEncInfo->CipherHeaderSize, 0x20);

  VarEncInfo->DecryptInPlace = TRUE;
  Status = DecryptVariable (VarEncInfo);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataType, 6);
  UT_ASSERT_EQUAL (VarEncInfo->CipherHeaderSize, 0x20);
  UT_ASSERT_EQUAL (VarEncInfo->PlainDataSize, sizeof (mTestVar3Data));
  UT_ASSERT_MEM_EQUAL (VarEncInfo->PlainData, mTestVar3Data, VarEncInfo->PlainDataSize);
  UT_ASSERT_MEM_EQUAL (mTestVar3CipherData + 0x20, mTestVar3Data, VarEncInfo->PlainDataSize);

  VarEncInfo->PlainData = NULL;
  VarEncInfo->PlainDataSize = 0;
  Status = GetCipherInfo (VarEncInfo);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);
  UT_ASSERT_EQUAL (VarEncInfo->PlainDataSize, sizeof (mTestVar3Data));
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataType, 0);
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataSize, 0);
  UT_ASSERT_EQUAL (VarEncInfo->CipherHeaderSize, 0x20);
  UT_ASSERT_NOT_NULL (VarEncInfo->PlainData);
  UT_ASSERT_MEM_EQUAL (VarEncInfo->PlainData, mTestVar3Data, VarEncInfo->PlainDataSize);


  //
  // TestVar4
  //
  VarEncInfo = &mTestVar4_d;

  Status = GetCipherInfo (VarEncInfo);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);
  UT_ASSERT_EQUAL (VarEncInfo->PlainDataSize, sizeof (mTestVar4Data));
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataType, 6);
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataSize, sizeof (mTestVar4CipherData));
  UT_ASSERT_EQUAL (VarEncInfo->CipherHeaderSize, 0x20);

  VarEncInfo->DecryptInPlace = TRUE;
  Status = DecryptVariable (VarEncInfo);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataType, 6);
  UT_ASSERT_EQUAL (VarEncInfo->CipherHeaderSize, 0x20);
  UT_ASSERT_EQUAL (VarEncInfo->PlainDataSize, sizeof (mTestVar4Data));
  UT_ASSERT_MEM_EQUAL (VarEncInfo->PlainData, mTestVar4Data, VarEncInfo->PlainDataSize);
  UT_ASSERT_MEM_EQUAL (mTestVar4CipherData + 0x20, mTestVar4Data, VarEncInfo->PlainDataSize);

  VarEncInfo->PlainData = NULL;
  VarEncInfo->PlainDataSize = 0;
  Status = GetCipherInfo (VarEncInfo);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);
  UT_ASSERT_EQUAL (VarEncInfo->PlainDataSize, sizeof (mTestVar4Data));
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataType, 0);
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataSize, 0);
  UT_ASSERT_EQUAL (VarEncInfo->CipherHeaderSize, 0x20);
  UT_ASSERT_NOT_NULL (VarEncInfo->PlainData);
  UT_ASSERT_MEM_EQUAL (VarEncInfo->PlainData, mTestVar4Data, VarEncInfo->PlainDataSize);

  //
  // TestVar5
  //
  VarEncInfo = &mTestVar5_d;

  Status = GetCipherInfo (VarEncInfo);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);
  UT_ASSERT_EQUAL (VarEncInfo->PlainDataSize, sizeof (mTestVar5Data));
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataType, 6);
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataSize, sizeof (mTestVar5CipherData));
  UT_ASSERT_EQUAL (VarEncInfo->CipherHeaderSize, 0x20);

  VarEncInfo->DecryptInPlace = TRUE;
  Status = DecryptVariable (VarEncInfo);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataType, 6);
  UT_ASSERT_EQUAL (VarEncInfo->CipherHeaderSize, 0x20);
  UT_ASSERT_EQUAL (VarEncInfo->PlainDataSize, sizeof (mTestVar5Data));
  UT_ASSERT_MEM_EQUAL (VarEncInfo->PlainData, mTestVar5Data, VarEncInfo->PlainDataSize);
  UT_ASSERT_MEM_EQUAL (mTestVar5CipherData + 0x20, mTestVar5Data, VarEncInfo->PlainDataSize);

  VarEncInfo->PlainData = NULL;
  VarEncInfo->PlainDataSize = 0;
  Status = GetCipherInfo (VarEncInfo);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);
  UT_ASSERT_EQUAL (VarEncInfo->PlainDataSize, sizeof (mTestVar5Data));
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataType, 0);
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataSize, 0);
  UT_ASSERT_EQUAL (VarEncInfo->CipherHeaderSize, 0x20);
  UT_ASSERT_NOT_NULL (VarEncInfo->PlainData);
  UT_ASSERT_MEM_EQUAL (VarEncInfo->PlainData, mTestVar5Data, VarEncInfo->PlainDataSize);

  //
  // TestVar6
  //
  VarEncInfo = &mTestVar6_d;

  Status = GetCipherInfo (VarEncInfo);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);
  UT_ASSERT_EQUAL (VarEncInfo->PlainDataSize, sizeof (mTestVar6Data));
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataType, 6);
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataSize, sizeof (mTestVar6CipherData));
  UT_ASSERT_EQUAL (VarEncInfo->CipherHeaderSize, 0x20);

  VarEncInfo->DecryptInPlace = TRUE;
  Status = DecryptVariable (VarEncInfo);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataType, 6);
  UT_ASSERT_EQUAL (VarEncInfo->CipherHeaderSize, 0x20);
  UT_ASSERT_EQUAL (VarEncInfo->PlainDataSize, sizeof (mTestVar6Data));
  UT_ASSERT_MEM_EQUAL (VarEncInfo->PlainData, mTestVar6Data, VarEncInfo->PlainDataSize);
  UT_ASSERT_MEM_EQUAL (mTestVar6CipherData + 0x20, mTestVar6Data, VarEncInfo->PlainDataSize);

  VarEncInfo->PlainData = NULL;
  VarEncInfo->PlainDataSize = 0;
  Status = GetCipherInfo (VarEncInfo);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);
  UT_ASSERT_EQUAL (VarEncInfo->PlainDataSize, sizeof (mTestVar6Data));
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataType, 0);
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataSize, 0);
  UT_ASSERT_EQUAL (VarEncInfo->CipherHeaderSize, 0x20);
  UT_ASSERT_NOT_NULL (VarEncInfo->PlainData);
  UT_ASSERT_MEM_EQUAL (VarEncInfo->PlainData, mTestVar6Data, VarEncInfo->PlainDataSize);

  //
  // TestVar7
  //
  VarEncInfo = &mTestVar7_d;

  Status = GetCipherInfo (VarEncInfo);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);
  UT_ASSERT_EQUAL (VarEncInfo->PlainDataSize, sizeof (mTestVar7Data));
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataType, 6);
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataSize, sizeof (mTestVar7CipherData));
  UT_ASSERT_EQUAL (VarEncInfo->CipherHeaderSize, 0x20);

  VarEncInfo->DecryptInPlace = TRUE;
  Status = DecryptVariable (VarEncInfo);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataType, 6);
  UT_ASSERT_EQUAL (VarEncInfo->CipherHeaderSize, 0x20);
  UT_ASSERT_EQUAL (VarEncInfo->PlainDataSize, sizeof (mTestVar7Data));
  UT_ASSERT_MEM_EQUAL (VarEncInfo->PlainData, mTestVar7Data, VarEncInfo->PlainDataSize);
  UT_ASSERT_MEM_EQUAL (mTestVar7CipherData + 0x20, mTestVar7Data, VarEncInfo->PlainDataSize);

  VarEncInfo->PlainData = NULL;
  VarEncInfo->PlainDataSize = 0;
  Status = GetCipherInfo (VarEncInfo);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);
  UT_ASSERT_EQUAL (VarEncInfo->PlainDataSize, sizeof (mTestVar7Data));
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataType, 0);
  UT_ASSERT_EQUAL (VarEncInfo->CipherDataSize, 0);
  UT_ASSERT_EQUAL (VarEncInfo->CipherHeaderSize, 0x20);
  UT_ASSERT_NOT_NULL (VarEncInfo->PlainData);
  UT_ASSERT_MEM_EQUAL (VarEncInfo->PlainData, mTestVar7Data, VarEncInfo->PlainDataSize);

  return UNIT_TEST_PASSED;
}

typedef struct {
  CHAR16               *Description;
  CHAR16               *ClassName;
  UNIT_TEST_FUNCTION   Func;
  UNIT_TEST_PREREQ     PreReq;
  UNIT_TEST_CLEANUP    CleanUp;
  UNIT_TEST_CONTEXT    Context;
} TEST_DESC;

TEST_DESC mTcEncryptionVariableLib[] = {
    //
    // -----Description--------------------------------------Class----------------------Function---------------------------------Pre---------------------Post---------Context
    //
    {L"TestVariableEncryption()",     L"SecurityPkg.ProtectedVariable.Encryption",   TestVariableEncryption,  TestEncryptVariableSetup, TestEncryptVariableTearDown, NULL},
    {L"TestVariableDecryption()",     L"SecurityPkg.ProtectedVariable.Encryption",   TestVariableDecryption,  TestEncryptVariableSetup, TestEncryptVariableTearDown, NULL},
    {L"TestGetCipherInfo()",          L"SecurityPkg.ProtectedVariable.Encryption",   TestGetCipherInfo,       TestEncryptVariableSetup, TestEncryptVariableTearDown, NULL}
};

UINTN mTcEncryptionVariableLibNum = ARRAY_SIZE(mTcEncryptionVariableLib);

/**
  The main() function for setting up and running the tests.

  @retval EFI_SUCCESS on successful running.
  @retval Other error code on failure.
**/
int main()
{
  EFI_STATUS                Status;
  UNIT_TEST_FRAMEWORK       *Fw;
  UNIT_TEST_SUITE           *TestSuite;
  CHAR16                    ShortName[MAX_STRING_SIZE];
  UINTN                     TestIndex;

  Fw = NULL;
  TestSuite = NULL;

  AsciiStrToUnicodeStrS (gEfiCallerBaseName, ShortName, sizeof(ShortName)/sizeof(ShortName[0]));
  DEBUG((DEBUG_INFO, "%s v%s\n", UNIT_TEST_NAME, UNIT_TEST_VERSION));

  Status = InitUnitTestFramework (&Fw, UNIT_TEST_NAME, ShortName, UNIT_TEST_VERSION);
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "Failed in InitUnitTestFramework. Status = %r\n", Status));
    goto EXIT;
  }

  Status = CreateUnitTestSuite (&TestSuite, Fw, L"EncryptionVariabeLib Test Suite", L"SecurityPkg.ProtectedVariable.Encryption", NULL, NULL);
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "Failed in CreateUnitTestSuite for EncryptionVariabeLib Test Suite\n"));
    Status = EFI_OUT_OF_RESOURCES;
    goto EXIT;
  }

  for (TestIndex = 0; TestIndex < mTcEncryptionVariableLibNum; TestIndex++) {
    AddTestCase (TestSuite,
                 mTcEncryptionVariableLib[TestIndex].Description,
                 mTcEncryptionVariableLib[TestIndex].ClassName,
                 mTcEncryptionVariableLib[TestIndex].Func,
                 mTcEncryptionVariableLib[TestIndex].PreReq,
                 mTcEncryptionVariableLib[TestIndex].CleanUp,
                 mTcEncryptionVariableLib[TestIndex].Context);
  }

  //
  // Execute the tests.
  //
  Status = RunAllTestSuites(Fw);

EXIT:
  if (Fw != NULL) {
    FreeUnitTestFramework(Fw);
  }

  return Status;
}

