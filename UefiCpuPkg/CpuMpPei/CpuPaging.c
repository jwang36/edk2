/** @file
  Basic paging support for the CPU to enable Stack Guard.

Copyright (c) 2018, Intel Corporation. All rights reserved.<BR>

This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Register/CpuId.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/CpuLib.h>

#include "CpuMpPei.h"

#define IA32_PG_P                   BIT0
#define IA32_PG_RW                  BIT1
#define IA32_PG_U                   BIT2
#define IA32_PG_A                   BIT5
#define IA32_PG_D                   BIT6
#define IA32_PG_PS                  BIT7
#define IA32_PG_NX                  BIT63

#define PAGE_ATTRIBUTE_BITS         (IA32_PG_D | IA32_PG_A | IA32_PG_U |\
                                     IA32_PG_RW | IA32_PG_P)
#define PAGE_PROGATE_BITS           (IA32_PG_NX | PAGE_ATTRIBUTE_BITS)

#define PAGING_PAE_INDEX_MASK       0x1FF
#define PAGING_4K_ADDRESS_MASK_64   0x000FFFFFFFFFF000ull
#define PAGING_2M_ADDRESS_MASK_64   0x000FFFFFFFE00000ull
#define PAGING_1G_ADDRESS_MASK_64   0x000FFFFFC0000000ull

typedef enum {
  PageNone = 0,
  PageMin,
  Page4K = PageMin,
  Page2M,
  Page1G,
  PageMax = Page1G
} PAGE_ATTRIBUTE;

typedef struct {
  PAGE_ATTRIBUTE   Attribute;
  UINT64           Length;
  UINT64           AddressMask;
} PAGE_ATTRIBUTE_TABLE;

PAGE_ATTRIBUTE_TABLE mPageAttributeTable[] = {
  {PageNone,       0,                         0},
  {Page4K,  SIZE_4KB, PAGING_4K_ADDRESS_MASK_64},
  {Page2M,  SIZE_2MB, PAGING_2M_ADDRESS_MASK_64},
  {Page1G,  SIZE_1GB, PAGING_1G_ADDRESS_MASK_64},
};

EFI_STATUS
EFIAPI
MemoryDiscoveredPpiNotifyCallback (
  IN EFI_PEI_SERVICES           **PeiServices,
  IN EFI_PEI_NOTIFY_DESCRIPTOR  *NotifyDescriptor,
  IN VOID                       *Ppi
  );

EFI_PEI_NOTIFY_DESCRIPTOR  mPostMemNotifyList[] = {
  {
    (EFI_PEI_PPI_DESCRIPTOR_NOTIFY_CALLBACK | EFI_PEI_PPI_DESCRIPTOR_TERMINATE_LIST),
    &gEfiPeiMemoryDiscoveredPpiGuid,
    MemoryDiscoveredPpiNotifyCallback
  }
};

/**
  The function will check if IA32 PAE is supported.

  @retval TRUE      IA32 PAE is supported.
  @retval FALSE     IA32 PAE is not supported.

**/
BOOLEAN
IsIa32PaeSupported (
  VOID
  )
{
  UINT32                    RegEax;
  CPUID_VERSION_INFO_EDX    RegEdx;

  AsmCpuid (CPUID_SIGNATURE, &RegEax, NULL, NULL, NULL);
  if (RegEax >= CPUID_VERSION_INFO) {
    AsmCpuid (CPUID_VERSION_INFO, NULL, NULL, NULL, &RegEdx.Uint32);
    if (RegEdx.Bits.PAE != 0) {
      return TRUE;
    }
  }

  return FALSE;
}

/**
  This API provides a way to allocate memory for page table.

  @param  Pages                 The number of 4 KB pages to allocate.

  @return A pointer to the allocated buffer or NULL if allocation fails.

**/
VOID *
AllocatePageTableMemory (
  IN UINTN           Pages
  )
{
  return AllocatePages(Pages);
}

/**
  Return page table entry to match the address.

  @param[in]   Address          The address to be checked.
  @param[out]  PageAttributes   The page attribute of the page entry.

  @return The page entry.
**/
VOID *
GetPageTableEntry (
  IN  PHYSICAL_ADDRESS                  Address,
  OUT PAGE_ATTRIBUTE                    *PageAttribute
  )
{
  INTN                  Level;
  INTN                  Index;
  INTN                  EntryIndex[4];
  UINT64                *PageTable;
  UINT64                AddressEncMask;

  EntryIndex[3] = RShiftU64 (Address, 30) & PAGING_PAE_INDEX_MASK;
  EntryIndex[2] = RShiftU64 (Address, 21) & PAGING_PAE_INDEX_MASK;
  EntryIndex[1] = RShiftU64 (Address, 12) & PAGING_PAE_INDEX_MASK;
  EntryIndex[0] = -1;

  AddressEncMask = PcdGet64 (PcdPteMemoryEncryptionAddressOrMask);
  PageTable = (UINT64 *)(UINTN)(AsmReadCr3 () & PAGING_4K_ADDRESS_MASK_64);
  for (Level = 3; Level > 0; --Level) {
    Index = EntryIndex[Level];
    if (Index < 0) {
      break;
    }

    //
    // No mapping?
    //
    if (PageTable[Index] == 0) {
      *PageAttribute = PageNone;
      return NULL;
    }

    //
    // Page memory?
    //
    if ((PageTable[Index] & IA32_PG_PS) != 0 || Level == PageMin) {
      *PageAttribute = (PAGE_ATTRIBUTE)Level;
      return &PageTable[Index];
    }

    //
    // Page directory or table
    //
    PageTable = (UINT64 *)(UINTN)(PageTable[Index] &
                                  ~AddressEncMask &
                                  PAGING_4K_ADDRESS_MASK_64);
  }

  *PageAttribute = PageNone;
  return NULL;
}

/**
  This function splits one page entry to small page entries.

  @param[in]  PageEntry        The page entry to be splitted.
  @param[in]  PageAttribute    The page attribute of the page entry.
  @param[in]  SplitAttribute   How to split the page entry.

  @retval RETURN_SUCCESS            The page entry is splitted.
  @retval RETURN_UNSUPPORTED        The page entry does not support to be splitted.
  @retval RETURN_OUT_OF_RESOURCES   No resource to split page entry.
**/
RETURN_STATUS
SplitPage (
  IN  UINT64                            *PageEntry,
  IN  PAGE_ATTRIBUTE                    PageAttribute,
  IN  PAGE_ATTRIBUTE                    SplitAttribute
  )
{
  UINT64   BaseAddress;
  UINT64   *NewPageEntry;
  UINTN    Index;
  UINT64   AddressEncMask;

  if (SplitAttribute == PageNone || SplitAttribute >= PageAttribute) {
    ASSERT (SplitAttribute != PageNone);
    ASSERT (SplitAttribute < PageAttribute);
    return RETURN_INVALID_PARAMETER;
  }

  NewPageEntry = AllocatePageTableMemory (1);
  if (NewPageEntry == NULL) {
    return RETURN_OUT_OF_RESOURCES;
  }

  //
  // Split to just next smaller size of pages to get more compact page table.
  //
  SplitAttribute = PageAttribute - 1;
  AddressEncMask = PcdGet64 (PcdPteMemoryEncryptionAddressOrMask);
  BaseAddress    = *PageEntry & mPageAttributeTable[PageAttribute].AddressMask;
  for (Index = 0; Index < SIZE_4KB / sizeof(UINT64); Index++) {
    NewPageEntry[Index] = BaseAddress | AddressEncMask |
                          ((*PageEntry) & PAGE_PROGATE_BITS);

    if (SplitAttribute != PageMin) {
      NewPageEntry[Index] |= IA32_PG_PS;
    }

    BaseAddress += mPageAttributeTable[SplitAttribute].Length;
  }

  (*PageEntry) = (UINT64)(UINTN)NewPageEntry | AddressEncMask | PAGE_ATTRIBUTE_BITS;

  return RETURN_SUCCESS;
}

/**
  This function modifies the page attributes for the memory region specified
  by BaseAddress and Length from their current attributes to the attributes
  specified by Attributes.

  Caller should make sure BaseAddress and Length is at page boundary.

  @param[in]   BaseAddress      Start address of a memory region.
  @param[in]   Length           Size in bytes of the memory region.
  @param[in]   Attributes       Bit mask of attributes to modify.

  @retval RETURN_SUCCESS            The attributes were modified for the memory
                                    region.
  @retval RETURN_INVALID_PARAMETER  Length is zero; or,
                                    Attributes specified an illegal combination
                                    of attributes that cannot be set together; or
                                    Addressis not 4KB aligned.
  @retval RETURN_OUT_OF_RESOURCES   There are not enough system resources to modify
                                    the attributes.
  @retval RETURN_UNSUPPORTED        Cannot modify the attributes of given memory.

**/
RETURN_STATUS
EFIAPI
ConvertMemoryPageAttributes (
  IN  PHYSICAL_ADDRESS                  BaseAddress,
  IN  UINT64                            Length,
  IN  UINT64                            Attributes
  )
{
  UINT64                            *PageEntry;
  PAGE_ATTRIBUTE                    PageAttribute;
  RETURN_STATUS                     Status;
  EFI_PHYSICAL_ADDRESS              MaximumAddress;

  if (Length == 0 ||
      (BaseAddress & (SIZE_4KB - 1)) != 0 ||
      (Length & (SIZE_4KB - 1)) != 0) {

    ASSERT (Length > 0);
    ASSERT ((BaseAddress & (SIZE_4KB - 1)) == 0);
    ASSERT ((Length & (SIZE_4KB - 1)) == 0);

    return RETURN_INVALID_PARAMETER;
  }

  MaximumAddress = (EFI_PHYSICAL_ADDRESS)MAX_UINT32;
  if (BaseAddress > MaximumAddress ||
      Length > MaximumAddress ||
      (BaseAddress > MaximumAddress - (Length - 1))) {
    return RETURN_UNSUPPORTED;
  }

  //
  // Below logic is to check 2M/4K page to make sure we do not waste memory.
  //
  while (Length != 0) {
    PageEntry = GetPageTableEntry (BaseAddress, &PageAttribute);
    if (PageEntry == NULL) {
      return RETURN_UNSUPPORTED;
    }

    if (PageAttribute != Page4K) {
      Status = SplitPage (PageEntry, PageAttribute, Page4K);
      if (RETURN_ERROR (Status)) {
        return Status;
      }
      //
      // Do it again until the page is 4K.
      //
      continue;
    }

    if ((Attributes & IA32_PG_P) != 0) {
      *PageEntry |= (UINT64)IA32_PG_P;
    } else {
      *PageEntry &= ~((UINT64)IA32_PG_P);
    }

    //
    // Convert success, move to next
    //
    BaseAddress += SIZE_4KB;
    Length -= SIZE_4KB;
  }

  return RETURN_SUCCESS;
}

/**
  Allocates and fills in the Page Directory and Page Table Entries to
  establish a 4G page table.

  @return The address of page table.

**/
UINTN
Create4GPageTablesIa32Pae (
  VOID
  )
{
  UINT8                   PhysicalAddressBits;
  EFI_PHYSICAL_ADDRESS    PhysicalAddress;
  UINTN                   IndexOfPdpEntries;
  UINTN                   IndexOfPageDirectoryEntries;
  UINT32                  NumberOfPdpEntriesNeeded;
  UINT64                  *PageMap;
  UINT64                  *PageDirectoryPointerEntry;
  UINT64                  *PageDirectoryEntry;
  UINTN                   TotalPagesNum;
  UINTN                   PageAddress;
  UINT64                  AddressEncMask;

  //
  // Make sure AddressEncMask is contained to smallest supported address field
  //
  AddressEncMask = PcdGet64 (PcdPteMemoryEncryptionAddressOrMask);
  AddressEncMask &= PAGING_1G_ADDRESS_MASK_64;
  PhysicalAddressBits = 32;

  //
  // Calculate the table entries needed.
  //
  NumberOfPdpEntriesNeeded = (UINT32) LShiftU64 (1, (PhysicalAddressBits - 30));

  TotalPagesNum = NumberOfPdpEntriesNeeded + 1;
  PageAddress = (UINTN) AllocatePageTableMemory (TotalPagesNum);
  ASSERT (PageAddress != 0);

  PageMap = (VOID *) PageAddress;
  PageAddress += SIZE_4KB;

  PageDirectoryPointerEntry = PageMap;
  PhysicalAddress = 0;

  for (IndexOfPdpEntries = 0;
        IndexOfPdpEntries < NumberOfPdpEntriesNeeded;
        IndexOfPdpEntries++, PageDirectoryPointerEntry++) {
    //
    // Each Directory Pointer entries points to a page of Page Directory entires.
    // So allocate space for them and fill them in in the IndexOfPageDirectoryEntries loop.
    //
    PageDirectoryEntry = (VOID *) PageAddress;
    PageAddress += SIZE_4KB;

    //
    // Fill in a Page Directory Pointer Entries
    //
    *PageDirectoryPointerEntry = (UINT64) (UINTN) PageDirectoryEntry |
                                                  AddressEncMask |
                                                  IA32_PG_P;
    for (IndexOfPageDirectoryEntries = 0;
          IndexOfPageDirectoryEntries < 512;
          IndexOfPageDirectoryEntries++, PageDirectoryEntry++, PhysicalAddress += SIZE_2MB) {
      //
      // Fill in the Page Directory entries
      //
      *PageDirectoryEntry = (UINT64) PhysicalAddress | AddressEncMask |
                                     IA32_PG_RW | IA32_PG_P | IA32_PG_PS;
    }
  }

  ZeroMem (
    PageDirectoryPointerEntry,
    sizeof (*PageDirectoryPointerEntry) * (512 - IndexOfPdpEntries)
    );

  return (UINTN) PageMap;
}

/**
  Setup page tables and make them work.

**/
VOID
EnablePaging (
  VOID
  )
{
  UINTN       PageTable;

  PageTable = Create4GPageTablesIa32Pae ();
  AsmWriteCr3 (PageTable);
  AsmWriteCr4 (AsmReadCr4 () | BIT5);   // CR4.PAE
  AsmWriteCr0 (AsmReadCr0 () | BIT31);  // CR0.PG
}

/**
  Get the base address of current AP's stack.

  This function is called in AP's context and assumes that whole calling stacks
  (till this function) consumed by AP's wakeup procedure will not exceed 4KB.

  PcdCpuApStackSize must be configured with value taking the Guard page into
  account.

  @param[in,out] Buffer  The pointer to private data buffer.

**/
VOID
EFIAPI
GetStackBase (
  IN OUT VOID *Buffer
  )
{
  UINTN     Dummy;

  *(UINTN *)Buffer = ((UINTN)(&Dummy + BASE_4KB) & (~((UINTN)BASE_4KB - 1)))
                     - PcdGet32(PcdCpuApStackSize);
}

/**
  Setup stack Guard page at the stack base of each processor. BSP and APs have
  different way to get stack base address.

**/
VOID
SetupStackGuardPage (
  VOID
  )
{
  EFI_PEI_HOB_POINTERS        Hob;
  UINTN                       StackBase;
  UINTN                       NumberOfProcessors;
  UINTN                       Bsp;
  UINTN                       Index;

  //
  // For BSP
  //
  Hob.Raw = GetHobList ();
  while ((Hob.Raw = GetNextHob (EFI_HOB_TYPE_MEMORY_ALLOCATION, Hob.Raw)) != NULL) {
    if (CompareGuid (&gEfiHobMemoryAllocStackGuid,
                     &(Hob.MemoryAllocationStack->AllocDescriptor.Name))) {

      ConvertMemoryPageAttributes (
        Hob.MemoryAllocationStack->AllocDescriptor.MemoryBaseAddress,
        EFI_PAGE_SIZE,
        0
        );
      break;

    }
  }

  //
  // For APs
  //

  //
  // One extra page at the bottom of the stack is needed for Guard page.
  //
  if (PcdGet32(PcdCpuApStackSize) <= EFI_PAGE_SIZE) {
    DEBUG ((DEBUG_ERROR, "PcdCpuApStackSize is not big enough for Stack Guard!\n"));
    ASSERT (FALSE);
  }

  MpInitLibGetNumberOfProcessors(&NumberOfProcessors, NULL);
  MpInitLibWhoAmI (&Bsp);
  for (Index = 0; Index < NumberOfProcessors; ++Index) {
    if (Index == Bsp) {
      continue;
    }

    //
    // Ask AP to return is stack base address.
    //
    MpInitLibStartupThisAP(GetStackBase, Index, NULL, 0, (VOID *)&StackBase, NULL);
    //
    // Set Guard page at stack base address.
    //
    ConvertMemoryPageAttributes(StackBase, EFI_PAGE_SIZE, 0);
    DEBUG ((DEBUG_INFO, "Stack Guard set at %lx [cpu%lu]!\n",
            (UINT64)StackBase, (UINT64)Index));
  }

  //
  // Publish the changes of page table.
  //
  CpuFlushTlb ();
}

VOID
EFIAPI
StackOverFlow(
  IN OUT VOID *Buffer
  )
{
  STATIC UINTN    Level = 0;
  UINT8           BlowUp[1024];

  SetMem(BlowUp, sizeof(BlowUp), 0);
  if (Level < 1024) {
    ++Level;
    StackOverFlow(NULL);
  }
}

/**
  Enabl/setup stack guard for each processor if PcdCpuStackGuard is set to TRUE.

  Doing this in the memory-discovered callback is to make sure the Stack Guard
  feature to cover as most PEI code as possible.

  @param[in] PeiServices          General purpose services available to every PEIM.
  @param[in] NotifyDescriptor     The notification structure this PEIM registered on install.
  @param[in] Ppi                  The memory discovered PPI.  Not used.

  @retval EFI_SUCCESS             The function completed successfully.
  @retval others                  There's error in MP initialization.
**/
EFI_STATUS
EFIAPI
MemoryDiscoveredPpiNotifyCallback (
  IN EFI_PEI_SERVICES           **PeiServices,
  IN EFI_PEI_NOTIFY_DESCRIPTOR  *NotifyDescriptor,
  IN VOID                       *Ppi
  )
{
  EFI_STATUS      Status;
  BOOLEAN         InitStackGuard;

  //
  // Paging must be setup first. Otherwise the exception TSS setup during MP
  // initialization later will not contain paging information and then fail
  // the task switch (for the sake of stack switch).
  //
  InitStackGuard = FALSE;
  if (IsIa32PaeSupported () && PcdGetBool (PcdCpuStackGuard)) {
    EnablePaging ();
    InitStackGuard = TRUE;
  }

  Status = InitializeCpuMpWorker ();
  ASSERT_EFI_ERROR (Status);

  if (InitStackGuard) {
    SetupStackGuardPage ();
    //StackOverFlow (NULL);
    //MpInitLibStartupThisAP(StackOverFlow, 1, NULL, 0, NULL, NULL);
  }


  return Status;
}

