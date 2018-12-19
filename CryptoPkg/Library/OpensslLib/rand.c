# include <sys/types.h>
# include <Uefi.h>
#include <Library/BaseLib.h>
#include <openssl/rand.h>
#include "internal/rand_int.h"
#include <Protocol/Rng.h>
#include <Library/UefiBootServicesTableLib.h>

typedef struct rand_pool_st RAND_POOL;

int rand_pool_init(void)
{
    return 0;    
}


int rand_pool_add_additional_data(RAND_POOL *pool)
{  
  EFI_STATUS            Status;
  EFI_RNG_PROTOCOL      *rng;
  UINT8                 Rand;
  
  Status = gBS->LocateProtocol(&gEfiRngProtocolGuid, NULL, (VOID **)&rng);
  if (EFI_ERROR(Status)) {
    rng = NULL;
  }
  
  if (rng != NULL) {
    Status = rng->GetRNG (rng, NULL, 1, &Rand);
  }

  return rand_pool_add(pool, (unsigned char *)&Rand, sizeof(Rand), 0);
}


void rand_pool_cleanup(void)
{
}


size_t rand_pool_acquire_entropy(RAND_POOL *pool)
{  
  size_t bytes_needed;
  bytes_needed = rand_pool_bytes_needed(pool, 4 /*entropy_factor*/);           
 
  return rand_pool_entropy_available(pool);
}

void rand_pool_keep_random_devices_open(int keep)
{

}

void ossl_store_cleanup_int(void)
{
    
}
