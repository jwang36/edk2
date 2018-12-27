# include <sys/types.h>
# include <Uefi.h>
#include <Library/BaseLib.h>
#include <openssl/rand.h>
#include "internal/rand_int.h"
#include <Protocol/Rng.h>
#include <Library/UefiBootServicesTableLib.h>
#include <openssl/aes.h>
#include <Library/MemoryAllocationLib.h>
typedef struct rand_pool_st RAND_POOL;



/**
  Generates a 64-bit random number.

  if Rand is NULL, then ASSERT().

  @param[out] Rand     Buffer pointer to store the 64-bit random value.

  @retval TRUE         Random number generated successfully.
  @retval FALSE        Failed to generate the random number.

**/
BOOLEAN
EFIAPI
RandomNumber64 (
  OUT     UINT64                    *Rand
  )
{ 
  EFI_RNG_PROTOCOL      *rng;
  UINTN                 number = 8;
  UINT8                 *rand;
  
  ASSERT (Rand != NULL);  
  rand = AllocateZeroPool (number);

  gBS->LocateProtocol(&gEfiRngProtocolGuid, NULL, (VOID **)&rng);   // check wheather hardwrar support ?

  if (NULL != rng){
    rng->GetRNG (rng, NULL, number, rand);
    Rand = (UINT64*)rand;
  }
  return FALSE;
}

/**
  Generates a 128-bit random number.

  if Rand is NULL, then ASSERT().

  @param[out] Rand     Buffer pointer to store the 128-bit random value.

  @retval TRUE         Random number generated successfully.
  @retval FALSE        Failed to generate the random number.

**/
BOOLEAN
EFIAPI
RandomNumber128 (
  OUT     UINT64                    *Rand
  )
{
  ASSERT (Rand != NULL);

  //
  // Read first 64 bits
  //
  if (!RandomNumber64 (Rand)) {
    return FALSE;
  }

  //
  // Read second 64 bits
  //
  return RandomNumber64 (++Rand);
}


/**
  Calls RDRAND to fill a buffer of arbitrary size with random bytes.

  @param[in]   Length        Size of the buffer, in bytes,  to fill with.
  @param[out]  RandBuffer    Pointer to the buffer to store the random result.

  @retval EFI_SUCCESS        Random bytes generation succeeded.
  @retval EFI_NOT_READY      Failed to request random bytes.

**/
EFI_STATUS
EFIAPI
RdRandGetBytes (
  IN UINTN         Length,
  OUT UINT8        *RandBuffer
  )
{
  BOOLEAN     IsRandom = FALSE;
  UINT64      TempRand[2];

  while (Length > 0) {
    IsRandom = RandomNumber128 (TempRand);
    if (!IsRandom) {
      return EFI_NOT_READY;
    }
    if (Length >= sizeof (TempRand)) {
      WriteUnaligned64 ((UINT64*)RandBuffer, TempRand[0]);
      RandBuffer += sizeof (UINT64);
      WriteUnaligned64 ((UINT64*)RandBuffer, TempRand[1]);
      RandBuffer += sizeof (UINT64);
      Length -= sizeof (TempRand);
    } else {
      CopyMem (RandBuffer, TempRand, Length);
      Length = 0;
    }
  }

  return EFI_SUCCESS;
}

/**
  Creates a 128bit random value that is fully forward and backward prediction resistant,
  suitable for seeding a NIST SP800-90 Compliant, FIPS 1402-2 certifiable SW DRBG.
  This function takes multiple random numbers through RDRAND without intervening
  delays to ensure reseeding and performs AES-CBC-MAC over the data to compute the
  seed value.
  
  @param[out]  SeedBuffer    Pointer to a 128bit buffer to store the random seed.

  @retval EFI_SUCCESS        Random seed generation succeeded.
  @retval EFI_NOT_READY      Failed to request random bytes.

**/
EFI_STATUS
EFIAPI
RdRandGetSeed128 (
  OUT UINT8        *SeedBuffer
  )
{
  EFI_STATUS  Status;
  UINT8       RandByte[16];
  UINT8       Key[16];
  UINT8       Ffv[16];
  UINT8       Xored[16];
  UINT32      Index;
  UINT32      Index2;
  AES_KEY     *key;
  //
  // Chose an arbitary key and zero the feed_forward_value (FFV)
  //
  for (Index = 0; Index < 16; Index++) {
    Key[Index] = (UINT8) Index;
    Ffv[Index] = 0;
  }

  //
  // Perform CBC_MAC over 32 * 128 bit values, with 10us gaps between 128 bit value
  // The 10us gaps will ensure multiple reseeds within the HW RNG with a large design margin.
  //
  for (Index = 0; Index < 32; Index++) {    
	gBS->Stall(10);
    Status = RdRandGetBytes (16, RandByte);
    if (EFI_ERROR (Status)) {
      return Status;
    }

    //
    // Perform XOR operations on two 128-bit value.
    //
    for (Index2 = 0; Index2 < 16; Index2++) {
      Xored[Index2] = RandByte[Index2] ^ Ffv[Index2];
    }
  
   key = NULL;
   key = AllocateZeroPool (sizeof (AES_KEY));
   key->rounds = 10;
  
   for (Index = 0; Index < 16; Index++) {
     key->rd_key[Index] = Key[Index];
   }
   
   AES_encrypt(Xored, Ffv, key);
  }

  for (Index = 0; Index < 16; Index++) {
    SeedBuffer[Index] = Ffv[Index];
  }

  return EFI_SUCCESS;
}


/**
  Generate high-quality entropy source through RDRAND.

  @param[in]   Length        Size of the buffer, in bytes, to fill with.
  @param[out]  Entropy       Pointer to the buffer to store the entropy data.

  @retval EFI_SUCCESS        Entropy generation succeeded.
  @retval EFI_NOT_READY      Failed to request random data.

**/
EFI_STATUS
EFIAPI
RdRandGenerateEntropy (
  IN UINTN         Length,
  OUT UINT8        *Entropy
  )
{
  EFI_STATUS  Status;
  UINTN       BlockCount;
  UINT8       Seed[16];
  UINT8       *Ptr;

  Status     = EFI_NOT_READY;
  BlockCount = Length / 16;
  Ptr        = (UINT8 *)Entropy;

  //
  // Generate high-quality seed for DRBG Entropy
  //
  while (BlockCount > 0) {
    Status = RdRandGetSeed128 (Seed);
    if (EFI_ERROR (Status)) {
      return Status;
    }
    CopyMem (Ptr, Seed, 16);

    BlockCount--;
    Ptr = Ptr + 16;
  }

  //
  // Populate the remained data as request.
  //
  Status = RdRandGetSeed128 (Seed);
  if (EFI_ERROR (Status)) {
    return Status;
  }
  CopyMem (Ptr, Seed, (Length % 16));

  return Status;
}


int rand_pool_init(void)
{
    return 0;    
}

int rand_pool_add_nonce_data(RAND_POOL *pool)
{
	struct {
	  UINT64				MonotonicCount;
	  UINT8 				Rand;
	  UINT64                TimerValue;
	} data = { 0 };
	
	
	EFI_STATUS			  Status;
	EFI_RNG_PROTOCOL	  *rng;
	UINT8				  Rand;
	UINT64				  MonotonicCount;
	
	Status = gBS->LocateProtocol(&gEfiRngProtocolGuid, NULL, (VOID **)&rng);
	if (EFI_ERROR(Status)) {
	  rng = NULL;
	}
	
	if (rng != NULL) {
	  Status = rng->GetRNG (rng, NULL, 1, &Rand);
	}
	 gBS->GetNextMonotonicCount (&MonotonicCount);
	data.TimerValue = AsmReadTsc ();
	data.Rand = Rand;
	data.MonotonicCount = MonotonicCount;
	return rand_pool_add(pool, (unsigned char *)&data, sizeof(data), 0);

}


int rand_pool_add_additional_data(RAND_POOL *pool)
{     
  struct {
    UINT64                MonotonicCount;
	UINT8                 Rand;
  } data = { 0 };
  
  EFI_STATUS            Status;
  EFI_RNG_PROTOCOL      *rng;
  UINT8                 Rand;
  UINT64                MonotonicCount;
  
  Status = gBS->LocateProtocol(&gEfiRngProtocolGuid, NULL, (VOID **)&rng);
  if (EFI_ERROR(Status)) {
    rng = NULL;
  }
  
  if (rng != NULL) {
    Status = rng->GetRNG (rng, NULL, 1, &Rand);
  }
  
  gBS->GetNextMonotonicCount (&MonotonicCount);

  return rand_pool_add(pool, (unsigned char *)&data, sizeof(data), 0);
  
}


void rand_pool_cleanup(void)
{

}


size_t rand_pool_acquire_entropy(RAND_POOL *pool)
{    
  UINT64                    TimerValue;
  size_t                    bytes_needed;
  UINT64                    MonotonicCount; 
  UINT8                      RNGValue;
  
  gBS->GetNextMonotonicCount (&MonotonicCount);
  TimerValue = AsmReadTsc (); 
  bytes_needed = rand_pool_bytes_needed(pool, 4 /*entropy_factor*/); 

  RdRandGenerateEntropy (bytes_needed, &RNGValue); 
  return rand_pool_entropy_available(pool);
}

void rand_pool_keep_random_devices_open(int keep)
{

}

void ossl_store_cleanup_int(void)
{
    
}
