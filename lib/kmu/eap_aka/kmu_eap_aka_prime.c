
#include "kmu_eap_aka_prime.h"
#include "kmu/eap/kmu_eap.h"
#include "kmu/crypt/kmu_base64.h"

void kmu_prf_prime(uint8_t *key, size_t key_len, uint8_t *input, size_t input_len, uint8_t *output, size_t output_len)
{
    // ogs_assert(key);
    // ogs_assert(input);

    int i = 0;
    int round = output_len / 32 + 1;  
    uint8_t *s = NULL;

    uint8_t **T = calloc(round, sizeof(uint8_t *));
   
    for (i = 0; i < round ; i++){
        int s_len = (i == 0 ? 0 : 32) + input_len + 1;

        s = calloc(1, s_len);
        
        if(!s){
            free(s);
        }

        int pos = 0;
        if (i == 0) {
            memcpy(s + pos, input, input_len);
            pos += input_len;
        } else {
            memcpy(s + pos, T[i - 1], 32);
            pos += 32;
            memcpy(s + pos, input, input_len);
            pos += input_len;
        }

        s[pos++] = (uint8_t)(i + 1);
        
        T[i] = malloc(KMU_SHA256_BLOCK_SIZE);
        
        kmu_hmac_sha256(key, key_len , s, s_len,  T[i], 32);

        free(s);
        
    } 

    size_t total_len = round * 32;
    uint8_t result[total_len];

    for (i = 0; i < round; i++) {
        memcpy(result + i * 32, T[i], 32);
        free(T[i]);
    }

    memcpy(output, result, output_len);
}

void kmu_eap_aka_prime_fs_key_generation(uint8_t *priv_key_ecdhe, uint8_t *pub_key_ecdhe){

    // generate random private key
    priv_key_ecdhe[0] &= 248;
    priv_key_ecdhe[31] &= 127;
    priv_key_ecdhe[31] |= 64;

    static const uint8_t curve25519_basepoint[32] = {9};
    
    kmu_curve25519_donna(pub_key_ecdhe, priv_key_ecdhe, curve25519_basepoint);
}

void kmu_eap_aka_prime_fs_generate_shared_key(uint8_t *shared_key, uint8_t *priv_key_ecdhe, uint8_t *pub_key_ecdhe){
    kmu_curve25519_donna(shared_key, priv_key_ecdhe, pub_key_ecdhe);
}

void kmu_eap_aka_prime_hpqc_xwing_key_generation(uint8_t *decapsulation_key, uint8_t *encapsulation_key){
    uint8_t expanded[96];
    uint8_t sk[32];

    OQS_randombytes(sk, 32);

    OQS_SHA3_shake256(expanded, 96, sk, 32);

    uint8_t public_key[OQS_KEM_ml_kem_768_length_public_key];
    uint8_t secret_key[OQS_KEM_ml_kem_768_length_secret_key];
    uint8_t seed[64];

    memcpy(seed, expanded, 64);
    OQS_KEM_ml_kem_768_keypair_derand(public_key,secret_key, seed);

    uint8_t sk_X[32];
    uint8_t pk_X[32];
    static const uint8_t x25519_base[32] = {9};

    memcpy(sk_X, expanded+64, 32);
    kmu_curve25519_donna(pk_X, sk_X, x25519_base);

    memcpy(decapsulation_key, sk, 32);
    memcpy(encapsulation_key, public_key, 1184);
    memcpy(encapsulation_key+1184, pk_X , 32);
}

void kmu_eap_aka_prime_pq_kem_key_generation(uint8_t *public_key_pq_kem,uint8_t *secret_key_pq_kem){
    OQS_KEM_ml_kem_768_keypair(public_key_pq_kem, secret_key_pq_kem);
}

void kmu_eap_aka_prime_hpqc_xwing_decapsulate(uint8_t *shared_key, uint8_t *ct_xwing, uint8_t *sk_xwing){
     // X-Wing 
     uint8_t ct_M[1088];
     uint8_t ct_X[32];
     uint8_t ss_M[32];
     uint8_t ss_X[32];

     memcpy(ct_M,ct_xwing, 1088);
     memcpy(ct_X,ct_xwing+1088, 32);

     // Decapsulate key (sk)

     uint8_t expanded[96];
 
     OQS_SHA3_shake256(expanded, 96, sk_xwing, 32);
 
     uint8_t pk_M[OQS_KEM_ml_kem_768_length_public_key];
     uint8_t sk_M[OQS_KEM_ml_kem_768_length_secret_key];
     uint8_t seed[64];
 
     memcpy(seed, expanded, 64);
     OQS_KEM_ml_kem_768_keypair_derand(pk_M,sk_M, seed);

     uint8_t sk_X[32];
     uint8_t pk_X[32];
     static const uint8_t x25519_base[32] = {9};

     memcpy(sk_X, expanded+64, 32);

     kmu_curve25519_donna(pk_X, sk_X, x25519_base);

     // we have sk_M, pk_M, sk_X, pk_X

     OQS_KEM_ml_kem_768_decaps(ss_M, ct_M, sk_M);

     kmu_curve25519_donna(ss_X, sk_X, ct_X);

     // combiner 

     uint8_t XWingLabel[6] = {
         0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c
     };

     uint8_t combiner_output[134];
     memcpy(combiner_output,ss_M, 32);
     memcpy(combiner_output+32,ss_X, 32);
     memcpy(combiner_output+64,ct_X, 32);
     memcpy(combiner_output+96,pk_X, 32);
     memcpy(combiner_output+128,XWingLabel, 6);

     OQS_SHA3_sha3_256(shared_key,combiner_output,134);
}

void kmu_eap_aka_prime_pq_kem_decapsulate(uint8_t *shared_key, uint8_t *ct, uint8_t *sk){
    OQS_KEM_ml_kem_768_decaps(shared_key, ct, sk);
}

void kmu_eap_aka_prime_generate_mk(uint8_t *ik_prime,uint8_t *ck_prime, char *input_supi, uint8_t *mk){

    size_t key_len = 32;

    uint8_t key_prf[key_len];
    memcpy(key_prf, ik_prime, 16);
    memcpy(key_prf+16, ck_prime, 16);

    const char *prefix = "EAP-AKA'";
    char *supi = kmu_id_get_value(input_supi);
    size_t input_len = strlen(prefix) + strlen(supi);

    uint8_t input[input_len];
    size_t pos = 0;
    size_t i;

    for (i = 0; i < strlen(prefix); i++) {
        input[pos] = (uint8_t)prefix[i];  
        pos++;
    }
    
    for (i = 0; i < strlen(supi); i++) {
        input[pos] = (uint8_t)supi[i];  
        pos++;
    }
    // output master key (MK) is 1664 bits = 208 bytes
    size_t mk_len = 208; 

    kmu_prf_prime(key_prf, key_len, input, input_len, mk, mk_len);
}


void kmu_eap_aka_prime_generate_mk_shared(uint8_t *ik_prime,uint8_t *ck_prime,uint8_t *shared_key, char *input_supi, uint8_t *mk_shared){
    size_t key_len = 64;

    uint8_t key_prf[key_len];
    memcpy(key_prf, ik_prime, 16);
    memcpy(key_prf+16, ck_prime, 16);
    memcpy(key_prf+32, shared_key, 32);

    const char *prefix = "EAP-AKA' FS";
    char *supi = kmu_id_get_value(input_supi);
    size_t input_len = strlen(prefix) + strlen(supi);

    uint8_t input[input_len];
    size_t pos = 0;
    size_t i;

    for (i = 0; i < strlen(prefix); i++) {
        input[pos] = (uint8_t)prefix[i];  
        pos++;
    }
    
    for (i = 0; i < strlen(supi); i++) {
        input[pos] = (uint8_t)supi[i];  
        pos++;
    }
    // output master key (MK) ECDHE/Shared is 1280 bits = 160 bytes
    size_t mk_shared_len = 160; 

    kmu_prf_prime(key_prf, key_len, input, input_len, mk_shared, mk_shared_len);
}

void kmu_eap_aka_prime_generate_mk_pq_shared(uint8_t *ik_prime,uint8_t *ck_prime,uint8_t *shared_key, char *input_supi, uint8_t *input_ct, uint8_t *mk_shared){
    size_t key_len = 64;

    uint8_t key_prf[key_len];
    memcpy(key_prf, ik_prime, 16);
    memcpy(key_prf+16, ck_prime, 16);
    memcpy(key_prf+32, shared_key, 32);

    const char *prefix = "EAP-AKA' FS";
    char *supi = kmu_id_get_value(input_supi);
    size_t input_len = strlen(prefix) + strlen(supi) + 1088;

    uint8_t input[input_len];
    size_t pos = 0;
    size_t i;

    for (i = 0; i < strlen(prefix); i++) {
        input[pos] = (uint8_t)prefix[i];  
        pos++;
    }
    
    for (i = 0; i < strlen(supi); i++) {
        input[pos] = (uint8_t)supi[i];  
        pos++;
    }
    
    for (i = 0; i < 1088; i++) {
        input[pos] = input_ct[i];  
        pos++;
    }
    // output master key (MK) ECDHE/Shared is 1280 bits = 160 bytes
    size_t mk_shared_len = 160; 

    kmu_prf_prime(key_prf, key_len, input, input_len, mk_shared, mk_shared_len);
}

char *kmu_eap_aka_prime_generate_eap_request_payload(uint8_t *rand, uint8_t *autn, uint8_t *k_aut, char *serving_network_name){

    uint8_t data_attribute[KMU_MAX_EAP_PAYLOAD_LEN];

    uint8_t at_rand[KMU_EAP_AKA_ATTRIBUTE_AT_RAND_LENGTH]; // 20
    uint8_t at_autn[KMU_EAP_AKA_ATTRIBUTE_AT_AUTN_LENGTH]; // 20
    uint8_t at_kdf[KMU_EAP_AKA_ATTRIBUTE_AT_KDF_LENGTH]; // 4
    uint8_t at_mac[KMU_EAP_AKA_ATTRIBUTE_AT_MAC_LENGTH]; // 20
    size_t at_kdf_input_length = ((strlen(serving_network_name) + 3)/4 + 1)*4; //36
    uint8_t at_kdf_input[at_kdf_input_length]; 

    // encode and append all attribute 
    size_t offset = 0;
    // AT_RAND
    kmu_eap_aka_encode_attribute(KMU_EAP_AKA_ATTRIBUTE_AT_RAND, rand, 16, at_rand);
    memcpy(data_attribute + offset, at_rand, KMU_EAP_AKA_ATTRIBUTE_AT_RAND_LENGTH);
    offset+=KMU_EAP_AKA_ATTRIBUTE_AT_RAND_LENGTH;
    
    // AT_AUTN
    kmu_eap_aka_encode_attribute(KMU_EAP_AKA_ATTRIBUTE_AT_AUTN, autn, 16, at_autn);
    memcpy(data_attribute + offset, at_autn, KMU_EAP_AKA_ATTRIBUTE_AT_AUTN_LENGTH);
    offset+=KMU_EAP_AKA_ATTRIBUTE_AT_AUTN_LENGTH;
    
    // AT_KDF
    kmu_eap_aka_encode_attribute(KMU_EAP_AKA_ATTRIBUTE_AT_KDF, NULL, 0, at_kdf);
    memcpy(data_attribute + offset, at_kdf, KMU_EAP_AKA_ATTRIBUTE_AT_KDF_LENGTH);
    offset+=KMU_EAP_AKA_ATTRIBUTE_AT_KDF_LENGTH;

    // AT_KDF_INPUT
    kmu_eap_aka_encode_attribute(KMU_EAP_AKA_ATTRIBUTE_AT_KDF_INPUT, serving_network_name, strlen(serving_network_name), at_kdf_input);
    memcpy(data_attribute + offset, at_kdf_input, at_kdf_input_length);
    offset+=at_kdf_input_length;

     // AT_MAC
    kmu_eap_aka_encode_attribute(KMU_EAP_AKA_ATTRIBUTE_AT_MAC, NULL, 16, at_mac);
    memcpy(data_attribute + offset, at_mac, KMU_EAP_AKA_ATTRIBUTE_AT_MAC_LENGTH);
    offset+=KMU_EAP_AKA_ATTRIBUTE_AT_MAC_LENGTH;
    
    // create eap_request 
    size_t eap_request_length = sizeof(kmu_eap_aka_packet_t) + offset;
    kmu_eap_aka_packet_t *eap_request_packet = malloc(eap_request_length);

    uint8_t eap_request[eap_request_length];
    
    kmu_eap_aka_build_request(eap_request_packet, KMU_EAP_AKA_SUBTYPE_AKA_CHALLENGE, offset, data_attribute);
    kmu_eap_aka_encode_packet(eap_request_packet, eap_request);

    //mac calculation 
    kmu_hmac_sha256(k_aut, KMU_SHA256_DIGEST_SIZE, eap_request, eap_request_length, at_mac+4, KMU_SHA256_DIGEST_SIZE);

    //copy back at_mac
    memcpy(eap_request + (eap_request_length - KMU_EAP_AKA_ATTRIBUTE_AT_MAC_LENGTH), at_mac, KMU_EAP_AKA_ATTRIBUTE_AT_MAC_LENGTH);

    //char eap_request_base64[((eap_request_length + 2) / 3) * 4 + 1];

    char *eap_request_base64 = malloc(((eap_request_length + 2) / 3) * 4 + 1);
    
    kmu_base64_encode_binary(eap_request_base64, eap_request, eap_request_length);


    return eap_request_base64;


}

char *kmu_eap_aka_prime_generate_eap_request_payload_fs(uint8_t *rand, uint8_t *autn, uint8_t *k_aut, char *serving_network_name, uint8_t *pub_key_ecdhe){

    uint8_t data_attribute[KMU_MAX_EAP_PAYLOAD_LEN];

    uint8_t at_rand[KMU_EAP_AKA_ATTRIBUTE_AT_RAND_LENGTH]; // 20
    uint8_t at_autn[KMU_EAP_AKA_ATTRIBUTE_AT_AUTN_LENGTH]; // 20
    uint8_t at_kdf[KMU_EAP_AKA_ATTRIBUTE_AT_KDF_LENGTH]; // 4
    uint8_t at_mac[KMU_EAP_AKA_ATTRIBUTE_AT_MAC_LENGTH]; // 20
    size_t at_kdf_input_length = ((strlen(serving_network_name) + 3)/4 + 1)*4; //36
    uint8_t at_kdf_input[at_kdf_input_length]; 
    uint8_t at_kdf_fs[KMU_EAP_AKA_ATTRIBUTE_AT_KDF_LENGTH]; // 4
    uint8_t at_pub_ecdhe[KMU_EAP_AKA_ATTRIBUTE_AT_PUB_ECDHE_LENGTH];

    // encode and append all attribute 
    size_t offset = 0;
    // AT_RAND
    kmu_eap_aka_encode_attribute(KMU_EAP_AKA_ATTRIBUTE_AT_RAND, rand, 16, at_rand);
    memcpy(data_attribute + offset, at_rand, KMU_EAP_AKA_ATTRIBUTE_AT_RAND_LENGTH);
    offset+=KMU_EAP_AKA_ATTRIBUTE_AT_RAND_LENGTH;
    
    // AT_AUTN
    kmu_eap_aka_encode_attribute(KMU_EAP_AKA_ATTRIBUTE_AT_AUTN, autn, 16, at_autn);
    memcpy(data_attribute + offset, at_autn, KMU_EAP_AKA_ATTRIBUTE_AT_AUTN_LENGTH);
    offset+=KMU_EAP_AKA_ATTRIBUTE_AT_AUTN_LENGTH;
    
    // AT_KDF
    kmu_eap_aka_encode_attribute(KMU_EAP_AKA_ATTRIBUTE_AT_KDF, NULL, 0, at_kdf);
    memcpy(data_attribute + offset, at_kdf, KMU_EAP_AKA_ATTRIBUTE_AT_KDF_LENGTH);
    offset+=KMU_EAP_AKA_ATTRIBUTE_AT_KDF_LENGTH;

    // AT_KDF_FS
    kmu_eap_aka_encode_attribute(KMU_EAP_AKA_ATTRIBUTE_AT_KDF_FS, NULL, 0, at_kdf_fs);
    memcpy(data_attribute + offset, at_kdf_fs, KMU_EAP_AKA_ATTRIBUTE_AT_KDF_FS_LENGTH);
    offset+=KMU_EAP_AKA_ATTRIBUTE_AT_KDF_FS_LENGTH;

    // AT_KDF_INPUT
    kmu_eap_aka_encode_attribute(KMU_EAP_AKA_ATTRIBUTE_AT_KDF_INPUT, serving_network_name, strlen(serving_network_name), at_kdf_input);
    memcpy(data_attribute + offset, at_kdf_input, at_kdf_input_length);
    offset+=at_kdf_input_length;

    // AT_PUB_ECDHE
    kmu_eap_aka_encode_attribute(KMU_EAP_AKA_ATTRIBUTE_AT_PUB_ECDHE, pub_key_ecdhe, 32, at_pub_ecdhe);
    memcpy(data_attribute + offset, at_pub_ecdhe, KMU_EAP_AKA_ATTRIBUTE_AT_PUB_ECDHE_LENGTH);
    offset+=KMU_EAP_AKA_ATTRIBUTE_AT_PUB_ECDHE_LENGTH;

    // AT_MAC
    kmu_eap_aka_encode_attribute(KMU_EAP_AKA_ATTRIBUTE_AT_MAC, NULL, 16, at_mac);
    memcpy(data_attribute + offset, at_mac, KMU_EAP_AKA_ATTRIBUTE_AT_MAC_LENGTH);
    offset+=KMU_EAP_AKA_ATTRIBUTE_AT_MAC_LENGTH;
    
    // create eap_request 
    size_t eap_request_length = sizeof(kmu_eap_aka_packet_t) + offset;
    kmu_eap_aka_packet_t *eap_request_packet = malloc(eap_request_length);

    uint8_t eap_request[eap_request_length];
    
    kmu_eap_aka_build_request(eap_request_packet, KMU_EAP_AKA_SUBTYPE_AKA_CHALLENGE, offset, data_attribute);
    kmu_eap_aka_encode_packet(eap_request_packet, eap_request);

    //mac calculation 
    kmu_hmac_sha256(k_aut, KMU_SHA256_DIGEST_SIZE, eap_request, eap_request_length, at_mac+4, KMU_SHA256_DIGEST_SIZE);

    //copy back at_mac
    memcpy(eap_request + (eap_request_length - KMU_EAP_AKA_ATTRIBUTE_AT_MAC_LENGTH), at_mac, KMU_EAP_AKA_ATTRIBUTE_AT_MAC_LENGTH);

    //char eap_request_base64[((eap_request_length + 2) / 3) * 4 + 1];
    char *eap_request_base64 = malloc(((eap_request_length + 2) / 3) * 4 + 1);    
    kmu_base64_encode_binary(eap_request_base64, eap_request, eap_request_length);

    return eap_request_base64;


}

char *kmu_eap_aka_prime_generate_eap_request_payload_hpqc(uint8_t *rand, uint8_t *autn, uint8_t *k_aut, char *serving_network_name, uint8_t *encapsulation_key){

    uint8_t data_attribute[KMU_MAX_EAP_PAYLOAD_LEN];

    uint8_t at_rand[KMU_EAP_AKA_ATTRIBUTE_AT_RAND_LENGTH]; // 20
    uint8_t at_autn[KMU_EAP_AKA_ATTRIBUTE_AT_AUTN_LENGTH]; // 20
    uint8_t at_kdf[KMU_EAP_AKA_ATTRIBUTE_AT_KDF_LENGTH]; // 4
    uint8_t at_mac[KMU_EAP_AKA_ATTRIBUTE_AT_MAC_LENGTH]; // 20
    size_t at_kdf_input_length = ((strlen(serving_network_name) + 3)/4 + 1)*4; //36
    uint8_t at_kdf_input[at_kdf_input_length]; 
    uint8_t at_kdf_fs[KMU_EAP_AKA_ATTRIBUTE_AT_KDF_LENGTH]; // 4
    uint8_t at_pub_hybrid[KMU_EAP_AKA_ATTRIBUTE_AT_PUB_HYBRID_LENGTH]; // 1220

    // encode and append all attribute 
    size_t offset = 0;
    // AT_RAND
    kmu_eap_aka_encode_attribute(KMU_EAP_AKA_ATTRIBUTE_AT_RAND, rand, 16, at_rand);
    memcpy(data_attribute + offset, at_rand, KMU_EAP_AKA_ATTRIBUTE_AT_RAND_LENGTH);
    offset+=KMU_EAP_AKA_ATTRIBUTE_AT_RAND_LENGTH;
    
    // AT_AUTN
    kmu_eap_aka_encode_attribute(KMU_EAP_AKA_ATTRIBUTE_AT_AUTN, autn, 16, at_autn);
    memcpy(data_attribute + offset, at_autn, KMU_EAP_AKA_ATTRIBUTE_AT_AUTN_LENGTH);
    offset+=KMU_EAP_AKA_ATTRIBUTE_AT_AUTN_LENGTH;
    
    // AT_KDF
    kmu_eap_aka_encode_attribute(KMU_EAP_AKA_ATTRIBUTE_AT_KDF, NULL, 0, at_kdf);
    memcpy(data_attribute + offset, at_kdf, KMU_EAP_AKA_ATTRIBUTE_AT_KDF_LENGTH);
    offset+=KMU_EAP_AKA_ATTRIBUTE_AT_KDF_LENGTH;

    // AT_KDF_FS
    kmu_eap_aka_encode_attribute(KMU_EAP_AKA_ATTRIBUTE_AT_KDF_FS, NULL, 0, at_kdf_fs);
    memcpy(data_attribute + offset, at_kdf_fs, KMU_EAP_AKA_ATTRIBUTE_AT_KDF_FS_LENGTH);
    offset+=KMU_EAP_AKA_ATTRIBUTE_AT_KDF_FS_LENGTH;

    // AT_KDF_INPUT
    kmu_eap_aka_encode_attribute(KMU_EAP_AKA_ATTRIBUTE_AT_KDF_INPUT, serving_network_name, strlen(serving_network_name), at_kdf_input);
    memcpy(data_attribute + offset, at_kdf_input, at_kdf_input_length);
    offset+=at_kdf_input_length;

    // AT_PUB_HYBRID
    kmu_eap_aka_encode_attribute(KMU_EAP_AKA_ATTRIBUTE_AT_PUB_HYBRID, encapsulation_key, 1216, at_pub_hybrid);
    memcpy(data_attribute + offset, at_pub_hybrid, KMU_EAP_AKA_ATTRIBUTE_AT_PUB_HYBRID_LENGTH);
    offset+=KMU_EAP_AKA_ATTRIBUTE_AT_PUB_HYBRID_LENGTH;

    // AT_MAC
    kmu_eap_aka_encode_attribute(KMU_EAP_AKA_ATTRIBUTE_AT_MAC, NULL, 16, at_mac);
    memcpy(data_attribute + offset, at_mac, KMU_EAP_AKA_ATTRIBUTE_AT_MAC_LENGTH);
    offset+=KMU_EAP_AKA_ATTRIBUTE_AT_MAC_LENGTH;
    
    // create eap_request 
    size_t eap_request_length = sizeof(kmu_eap_aka_packet_t) + offset;
    kmu_eap_aka_packet_t *eap_request_packet = malloc(eap_request_length);

    uint8_t eap_request[eap_request_length];
    
    kmu_eap_aka_build_request(eap_request_packet, KMU_EAP_AKA_SUBTYPE_AKA_CHALLENGE, offset, data_attribute);
    kmu_eap_aka_encode_packet(eap_request_packet, eap_request);

    //mac calculation 
    kmu_hmac_sha256(k_aut, KMU_SHA256_DIGEST_SIZE, eap_request, eap_request_length, at_mac+4, KMU_SHA256_DIGEST_SIZE);

    //copy back at_mac
    memcpy(eap_request + (eap_request_length - KMU_EAP_AKA_ATTRIBUTE_AT_MAC_LENGTH), at_mac, KMU_EAP_AKA_ATTRIBUTE_AT_MAC_LENGTH);

    //char eap_request_base64[((eap_request_length + 2) / 3) * 4 + 1];
    char *eap_request_base64 = malloc(((eap_request_length + 2) / 3) * 4 + 1);    
    kmu_base64_encode_binary(eap_request_base64, eap_request, eap_request_length);

    return eap_request_base64;


}


char *kmu_eap_aka_prime_generate_eap_request_payload_pq_kem(uint8_t *rand, uint8_t *autn, uint8_t *k_aut, char *serving_network_name, uint8_t *public_key_pq_kem){
    
    uint8_t data_attribute[KMU_MAX_EAP_PAYLOAD_LEN];

    uint8_t at_rand[KMU_EAP_AKA_ATTRIBUTE_AT_RAND_LENGTH]; // 20
    uint8_t at_autn[KMU_EAP_AKA_ATTRIBUTE_AT_AUTN_LENGTH]; // 20
    uint8_t at_kdf[KMU_EAP_AKA_ATTRIBUTE_AT_KDF_LENGTH]; // 4
    uint8_t at_mac[KMU_EAP_AKA_ATTRIBUTE_AT_MAC_LENGTH]; // 20
    size_t at_kdf_input_length = ((strlen(serving_network_name) + 3)/4 + 1)*4; //36
    uint8_t at_kdf_input[at_kdf_input_length]; 
    uint8_t at_kdf_fs[KMU_EAP_AKA_ATTRIBUTE_AT_KDF_LENGTH]; // 4
    uint8_t at_pub_kem[KMU_EAP_AKA_ATTRIBUTE_AT_PUB_KEM_LENGTH]; // 1188

    // encode and append all attribute 
    size_t offset = 0;
    // AT_RAND
    kmu_eap_aka_encode_attribute(KMU_EAP_AKA_ATTRIBUTE_AT_RAND, rand, 16, at_rand);
    memcpy(data_attribute + offset, at_rand, KMU_EAP_AKA_ATTRIBUTE_AT_RAND_LENGTH);
    offset+=KMU_EAP_AKA_ATTRIBUTE_AT_RAND_LENGTH;
    
    // AT_AUTN
    kmu_eap_aka_encode_attribute(KMU_EAP_AKA_ATTRIBUTE_AT_AUTN, autn, 16, at_autn);
    memcpy(data_attribute + offset, at_autn, KMU_EAP_AKA_ATTRIBUTE_AT_AUTN_LENGTH);
    offset+=KMU_EAP_AKA_ATTRIBUTE_AT_AUTN_LENGTH;
    
    // AT_KDF
    kmu_eap_aka_encode_attribute(KMU_EAP_AKA_ATTRIBUTE_AT_KDF, NULL, 0, at_kdf);
    memcpy(data_attribute + offset, at_kdf, KMU_EAP_AKA_ATTRIBUTE_AT_KDF_LENGTH);
    offset+=KMU_EAP_AKA_ATTRIBUTE_AT_KDF_LENGTH;

    // AT_KDF_FS
    kmu_eap_aka_encode_attribute(KMU_EAP_AKA_ATTRIBUTE_AT_KDF_FS, NULL, 0, at_kdf_fs);
    memcpy(data_attribute + offset, at_kdf_fs, KMU_EAP_AKA_ATTRIBUTE_AT_KDF_FS_LENGTH);
    offset+=KMU_EAP_AKA_ATTRIBUTE_AT_KDF_FS_LENGTH;

    // AT_KDF_INPUT
    kmu_eap_aka_encode_attribute(KMU_EAP_AKA_ATTRIBUTE_AT_KDF_INPUT, serving_network_name, strlen(serving_network_name), at_kdf_input);
    memcpy(data_attribute + offset, at_kdf_input, at_kdf_input_length);
    offset+=at_kdf_input_length;

    // AT_PUB_KEM
    kmu_eap_aka_encode_attribute(KMU_EAP_AKA_ATTRIBUTE_AT_PUB_KEM, public_key_pq_kem, 1184, at_pub_kem);
    memcpy(data_attribute + offset, at_pub_kem, KMU_EAP_AKA_ATTRIBUTE_AT_PUB_KEM_LENGTH);
    offset+=KMU_EAP_AKA_ATTRIBUTE_AT_PUB_KEM_LENGTH;

    // AT_MAC
    kmu_eap_aka_encode_attribute(KMU_EAP_AKA_ATTRIBUTE_AT_MAC, NULL, 16, at_mac);
    memcpy(data_attribute + offset, at_mac, KMU_EAP_AKA_ATTRIBUTE_AT_MAC_LENGTH);
    offset+=KMU_EAP_AKA_ATTRIBUTE_AT_MAC_LENGTH;
    
    // create eap_request 
    size_t eap_request_length = sizeof(kmu_eap_aka_packet_t) + offset;
    kmu_eap_aka_packet_t *eap_request_packet = malloc(eap_request_length);

    uint8_t eap_request[eap_request_length];
    
    kmu_eap_aka_build_request(eap_request_packet, KMU_EAP_AKA_SUBTYPE_AKA_CHALLENGE, offset, data_attribute);
    kmu_eap_aka_encode_packet(eap_request_packet, eap_request);

    //mac calculation 
    kmu_hmac_sha256(k_aut, KMU_SHA256_DIGEST_SIZE, eap_request, eap_request_length, at_mac+4, KMU_SHA256_DIGEST_SIZE);

    //copy back at_mac
    memcpy(eap_request + (eap_request_length - KMU_EAP_AKA_ATTRIBUTE_AT_MAC_LENGTH), at_mac, KMU_EAP_AKA_ATTRIBUTE_AT_MAC_LENGTH);

    //char eap_request_base64[((eap_request_length + 2) / 3) * 4 + 1];
    char *eap_request_base64 = malloc(((eap_request_length + 2) / 3) * 4 + 1);    
    kmu_base64_encode_binary(eap_request_base64, eap_request, eap_request_length);

    return eap_request_base64;
}

char *kmu_eap_aka_prime_generate_eap_success_payload(void){

    size_t eap_success_packet_length = 4;
    uint8_t eap_success[eap_success_packet_length];

    char *eap_response_base64 = malloc(((eap_success_packet_length + 2) / 3) * 4 + 1);
    kmu_eap_aka_packet_t *eap_response_packet = malloc(eap_success_packet_length);

    kmu_eap_aka_build_success(eap_response_packet);
    kmu_eap_aka_encode_packet(eap_response_packet,eap_success);
    kmu_base64_encode_binary(eap_response_base64, eap_success, eap_success_packet_length);

    return eap_response_base64;
}

bool kmu_eap_aka_prime_authenticate(char *eap_payload, uint8_t *k_aut){

    uint8_t eap_response_decoded[KMU_MAX_EAP_PAYLOAD_LEN];
    size_t eap_reponse_len = kmu_base64_decode_binary(eap_response_decoded,eap_payload);
    uint8_t eap_response_mac_input[eap_reponse_len];

    if (eap_reponse_len == 0)
        return false;

    uint8_t at_res[8];
    uint8_t at_mac[16];
    uint8_t xmac[KMU_SHA256_DIGEST_SIZE];
    kmu_eap_aka_decode_attribute(KMU_EAP_AKA_ATTRIBUTE_AT_RES, eap_response_decoded, eap_reponse_len, at_res);
    kmu_eap_aka_decode_attribute(KMU_EAP_AKA_ATTRIBUTE_AT_MAC, eap_response_decoded, eap_reponse_len, at_mac);

    kmu_eap_aka_clean_mac(KMU_EAP_AKA_ATTRIBUTE_AT_MAC, eap_response_decoded, eap_reponse_len, eap_response_mac_input);    

    //mac calculation 
    kmu_hmac_sha256(k_aut, 32, eap_response_mac_input, eap_reponse_len, xmac, KMU_SHA256_DIGEST_SIZE);

    if (memcmp(xmac, at_mac, KMU_SHA256_DIGEST_SIZE/2) != 0) {
        return false;
    }
    return true;
}

bool kmu_eap_aka_prime_authenticate_fs(char *eap_payload, uint8_t *k_aut, uint8_t *at_pub_ecdhe){

    uint8_t eap_response_decoded[KMU_MAX_EAP_PAYLOAD_LEN];
    size_t eap_reponse_len = kmu_base64_decode_binary(eap_response_decoded,eap_payload);
    uint8_t eap_response_mac_input[eap_reponse_len];

    if (eap_reponse_len == 0)
        return false;

    uint8_t at_res[8];
    uint8_t at_mac[16];
    uint8_t xmac[KMU_SHA256_DIGEST_SIZE];
    kmu_eap_aka_decode_attribute(KMU_EAP_AKA_ATTRIBUTE_AT_RES, eap_response_decoded, eap_reponse_len, at_res);
    kmu_eap_aka_decode_attribute(KMU_EAP_AKA_ATTRIBUTE_AT_MAC, eap_response_decoded, eap_reponse_len, at_mac);

    size_t fs_extension_status = kmu_eap_aka_decode_attribute(KMU_EAP_AKA_ATTRIBUTE_AT_PUB_ECDHE, eap_response_decoded, eap_reponse_len, at_pub_ecdhe);
    if(fs_extension_status == 0){
        return false;
    }

    kmu_eap_aka_clean_mac(KMU_EAP_AKA_ATTRIBUTE_AT_MAC, eap_response_decoded, eap_reponse_len, eap_response_mac_input);    

    //mac calculation 
    kmu_hmac_sha256(k_aut, 32, eap_response_mac_input, eap_reponse_len, xmac, KMU_SHA256_DIGEST_SIZE);

    if (memcmp(xmac, at_mac, KMU_SHA256_DIGEST_SIZE/2) != 0) {
        return false;
    }
    return true;
}


bool kmu_eap_aka_prime_authenticate_hpqc(char *eap_payload, uint8_t *k_aut, uint8_t *at_pub_hybrid){

    uint8_t eap_response_decoded[KMU_MAX_EAP_PAYLOAD_LEN];
    size_t eap_reponse_len = kmu_base64_decode_binary(eap_response_decoded,eap_payload);
    uint8_t eap_response_mac_input[eap_reponse_len];

    if (eap_reponse_len == 0)
        return false;

    uint8_t at_res[8];
    uint8_t at_mac[16];
    uint8_t xmac[KMU_SHA256_DIGEST_SIZE];
    kmu_eap_aka_decode_attribute(KMU_EAP_AKA_ATTRIBUTE_AT_RES, eap_response_decoded, eap_reponse_len, at_res);
    kmu_eap_aka_decode_attribute(KMU_EAP_AKA_ATTRIBUTE_AT_MAC, eap_response_decoded, eap_reponse_len, at_mac);

    size_t hpqc_extension_status = kmu_eap_aka_decode_attribute(KMU_EAP_AKA_ATTRIBUTE_AT_PUB_HYBRID, eap_response_decoded, eap_reponse_len, at_pub_hybrid);
    if(hpqc_extension_status == 0){
        return false;
    }

    kmu_eap_aka_clean_mac(KMU_EAP_AKA_ATTRIBUTE_AT_MAC, eap_response_decoded, eap_reponse_len, eap_response_mac_input);    

    //mac calculation 
    kmu_hmac_sha256(k_aut, 32, eap_response_mac_input, eap_reponse_len, xmac, KMU_SHA256_DIGEST_SIZE);

    if (memcmp(xmac, at_mac, KMU_SHA256_DIGEST_SIZE/2) != 0) {
        return false;
    }
    return true;
}

bool kmu_eap_aka_prime_authenticate_pq_kem(char *eap_payload, uint8_t *k_aut, uint8_t *at_kem_ct){

    uint8_t eap_response_decoded[KMU_MAX_EAP_PAYLOAD_LEN];
    size_t eap_reponse_len = kmu_base64_decode_binary(eap_response_decoded,eap_payload);
    uint8_t eap_response_mac_input[eap_reponse_len];

    if (eap_reponse_len == 0)
        return false;

    uint8_t at_res[8];
    uint8_t at_mac[16];
    uint8_t xmac[KMU_SHA256_DIGEST_SIZE];
    kmu_eap_aka_decode_attribute(KMU_EAP_AKA_ATTRIBUTE_AT_RES, eap_response_decoded, eap_reponse_len, at_res);
    kmu_eap_aka_decode_attribute(KMU_EAP_AKA_ATTRIBUTE_AT_MAC, eap_response_decoded, eap_reponse_len, at_mac);

    size_t pq_kem_extension_status = kmu_eap_aka_decode_attribute(KMU_EAP_AKA_ATTRIBUTE_AT_KEM_CT, eap_response_decoded, eap_reponse_len, at_kem_ct);
    if(pq_kem_extension_status == 0){
        return false;
    }

    kmu_eap_aka_clean_mac(KMU_EAP_AKA_ATTRIBUTE_AT_MAC, eap_response_decoded, eap_reponse_len, eap_response_mac_input);    

    //mac calculation 
    kmu_hmac_sha256(k_aut, 32, eap_response_mac_input, eap_reponse_len, xmac, KMU_SHA256_DIGEST_SIZE);

    if (memcmp(xmac, at_mac, KMU_SHA256_DIGEST_SIZE/2) != 0) {
        return false;
    }
    return true;
}