 
#ifndef KMU_KDF_H
#define KMU_KDF_H

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <endian.h>

#ifdef __cplusplus
extern "C" {
#endif
 
/* TS33.501 Annex A.3 : CK' and IK' derivation function */
void kmu_kdf_ck_prime_ik_prime(
        uint8_t *ck, uint8_t *ik,
        char *serving_network_name, uint8_t *sqn, uint8_t *ak,
        uint8_t *ck_prime, uint8_t *ik_prime);

#ifdef __cplusplus
}
#endif

#endif /* KMU_KDF_H */