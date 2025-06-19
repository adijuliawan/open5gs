
#ifndef KMU_EAP_AKA_PRIME_H
#define KMU_EAP_AKA_PRIME_H

#include "../crypt/kmu_sha2_hmac.h"
#include "../crypt/curve25519_donna.h"
#include "../crypt/kmu_common.h"
#include "../oqs/oqs.h"
#include "../oqs/sha3.h"


#ifdef __cplusplus
extern "C" {
#endif

void kmu_prf_prime(uint8_t *key, size_t key_len, uint8_t *input, size_t input_len, uint8_t *output, size_t output_len);

void kmu_eap_aka_prime_generate_mk(uint8_t *ik_prime,uint8_t *ck_prime, char *input_supi, uint8_t *mk);
void kmu_eap_aka_prime_generate_mk_shared(uint8_t *ik_prime,uint8_t *ck_prime,uint8_t *shared_key, char *input_supi, uint8_t *mk_shared);
void kmu_eap_aka_prime_generate_mk_pq_shared(uint8_t *ik_prime,uint8_t *ck_prime,uint8_t *shared_key, char *input_supi, uint8_t *input_ct, uint8_t *mk_shared);

// FS Extension
void kmu_eap_aka_prime_fs_key_generation(uint8_t *priv_key_ecdhe, uint8_t *pub_key_ecdhe);
void kmu_eap_aka_prime_fs_generate_shared_key(uint8_t *shared_key, uint8_t *priv_key_ecdhe, uint8_t *pub_key_ecdhe); 

// HPQC Extension
void kmu_eap_aka_prime_hpqc_xwing_key_generation(uint8_t *decapsulation_key, uint8_t *encapsulation_key);  
void kmu_eap_aka_prime_hpqc_xwing_decapsulate(uint8_t *shared_key, uint8_t *ct_xwing, uint8_t *sk_xwing);

//PQ KEM Extension
void kmu_eap_aka_prime_pq_kem_key_generation(uint8_t *public_key_pq_kem,uint8_t *secret_key_pq_kem);
void kmu_eap_aka_prime_pq_kem_decapsulate(uint8_t *shared_key, uint8_t *ct, uint8_t *sk);

// EAP-AKA' Request Payload Generation 
char *kmu_eap_aka_prime_generate_eap_request_payload(uint8_t *rand, uint8_t *autn, uint8_t *k_aut, char *serving_network_name);
char *kmu_eap_aka_prime_generate_eap_request_payload_fs(uint8_t *rand, uint8_t *autn, uint8_t *k_aut, char *serving_network_name, uint8_t *pub_key_ecdhe);
char *kmu_eap_aka_prime_generate_eap_request_payload_hpqc(uint8_t *rand, uint8_t *autn, uint8_t *k_aut, char *serving_network_name, uint8_t *encapsulation_key);
char *kmu_eap_aka_prime_generate_eap_request_payload_pq_kem(uint8_t *rand, uint8_t *autn, uint8_t *k_aut, char *serving_network_name, uint8_t *public_key_pq_kem);

// EAP-AKA' Success Payload Generation 
char *kmu_eap_aka_prime_generate_eap_success_payload(void);

// EAP-AKA' authenticate 
bool kmu_eap_aka_prime_authenticate(char *eap_payload, uint8_t *k_aut);
bool kmu_eap_aka_prime_authenticate_fs(char *eap_payload, uint8_t *k_aut, uint8_t *at_pub_ecdhe);
bool kmu_eap_aka_prime_authenticate_hpqc(char *eap_payload, uint8_t *k_aut, uint8_t *at_pub_hybrid);
bool kmu_eap_aka_prime_authenticate_pq_kem(char *eap_payload, uint8_t *k_aut, uint8_t *at_kem_ct);



#ifdef __cplusplus
}
#endif

#endif