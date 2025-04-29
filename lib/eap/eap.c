#include "eap.h"
#include <stdio.h>
#include "../core/ogs-core.h"
#include "../crypt/ogs-crypt.h"
#include "oqs/oqs.h"
#include "oqs/sha3.h"

uint8_t id = 100;
const uint16_t EAP_AKA_REQUEST_MIN_LENGTH = 8;

uint8_t eap_next_id(uint8_t id)
{
    id = (id + 1) % 256;
    return id;
}

void eap_aka_build_request(eap_aka_packet_t *packet, EapAkaSubType sub_type, size_t data_len, uint8_t *data)
{
    packet->code = EAP_CODE_REQUEST;
    packet->identifier = eap_next_id(id);
    packet->length = EAP_AKA_REQUEST_MIN_LENGTH + data_len;
    packet->type = EAP_METHOD_TYPE_AKA_PRIME;
    packet->sub_type = sub_type;
    memcpy(packet->data, data, data_len);
}

void eap_aka_parse_response(eap_aka_packet_t *packet, uint8_t *input)
{
    //if (!input || !packet) return;

    uint16_t total_len = (input[2] << 8) | input[3];
    if (total_len < 8) return;

    // Allocate and copy
    size_t payload_len = total_len - 8;

    packet->code       = input[0];
    packet->identifier = input[1];
    packet->length     = total_len;
    packet->type       = input[4];
    packet->sub_type   = input[5];

    memcpy(packet->data, input + 8, payload_len);
}

void eap_aka_build_success(eap_aka_packet_t *packet)
{
    packet->code = EAP_CODE_SUCCESS;
    packet->identifier = eap_next_id(id);
    packet->length = 4;
}

void eap_aka_build_failure(eap_aka_packet_t *packet)
{
    packet->code = EAP_CODE_FAILURE;
    packet->identifier = eap_next_id(id);
    packet->length = 4;
}

size_t eap_aka_encode_attribute(EapAkaAttributeType eap_aka_attribute_type, const void *input, size_t input_len, uint8_t *output)
{
    switch(eap_aka_attribute_type){
        case EAP_AKA_ATTRIBUTE_AT_RAND:
            output[0] = EAP_AKA_ATTRIBUTE_AT_RAND;
            output[1] = 5;
            output[2] = 0x00;
            output[3] = 0x00;
            memcpy(output+4, input, input_len);
            return 20;
            break;
        
        case EAP_AKA_ATTRIBUTE_AT_AUTN:
            output[0] = EAP_AKA_ATTRIBUTE_AT_AUTN;
            output[1] = 5;
            output[2] = 0x00;
            output[3] = 0x00;
            memcpy(output+4, input, input_len);
            return 20;
            break;
        
        case EAP_AKA_ATTRIBUTE_AT_MAC:
            output[0] = EAP_AKA_ATTRIBUTE_AT_MAC; 
            output[1] = 5;
            output[2] = output[3] = 0x00;
            memset(output + 4, 0x00, input_len);
            return 20;
            break;

        case EAP_AKA_ATTRIBUTE_AT_KDF:
            output[0] = EAP_AKA_ATTRIBUTE_AT_KDF;
            output[1] = 1;
            output[2] = 0x00;
            output[3] = 0x01;
            return 4;
            break;

        case EAP_AKA_ATTRIBUTE_AT_KDF_INPUT:
            
            // Total padded length (round up to multiple of 4)
            size_t padded_len = ((input_len + 3) / 4) * 4;
            size_t length_field = (padded_len / 4) + 1;

            output[0] = EAP_AKA_ATTRIBUTE_AT_KDF_INPUT;
            output[1] = (uint8_t)length_field;
            eap_int_to_bytes_be((uint16_t)input_len, output + 2);

            // Apply LEFT padding (zeros before data)
            memset(output + 4, 0x00, padded_len);
            if (input_len > padded_len) input_len = padded_len;
            memcpy(output + 4 + (padded_len - input_len), input, input_len);

            return length_field * 4;
            break;
        
        case EAP_AKA_ATTRIBUTE_AT_PUB_ECDHE:
            // X25519 : 32 bytes + 1 + 1 = 34 + 2 (padding) = 36/4 = 9(length)
            // P256-1 : 33 bytes + 1 + 1 = 35 + 1 (padding) = 36/4 = 9(length)
            output[0] = EAP_AKA_ATTRIBUTE_AT_PUB_ECDHE;
            output[1] = EAP_AKA_ATTRIBUTE_AT_PUB_ECDHE_LENGTH/4;
            memset(output + 2, 0x00, 34);
            memcpy(output + EAP_AKA_ATTRIBUTE_AT_PUB_ECDHE_LENGTH - input_len, input, input_len);
            return EAP_AKA_ATTRIBUTE_AT_PUB_ECDHE_LENGTH;
            break;
        
        case EAP_AKA_ATTRIBUTE_AT_PUB_HYBRID:
            // X-Wing : 1216 bytes + 2 + 1 = 1219 + 1 (padding) = 1220/4 = 305(length)
            output[0] = EAP_AKA_ATTRIBUTE_AT_PUB_HYBRID;
            size_t length_pub_hybrid = EAP_AKA_ATTRIBUTE_AT_PUB_HYBRID_LENGTH/4;
            eap_int_to_bytes_be((uint16_t)length_pub_hybrid, output + 1);

            memset(output + 3, 0x00, 1);
            memcpy(output + 4, input, 1216);
            return EAP_AKA_ATTRIBUTE_AT_PUB_HYBRID_LENGTH;
            break;
        
        case EAP_AKA_ATTRIBUTE_AT_KDF_FS:
            output[0] = EAP_AKA_ATTRIBUTE_AT_KDF_FS;
            output[1] = 1;
            output[2] = 0x00;
            output[3] = 0x01;
            return 4;
            break;

        default:
            return 0;
            break;
    }
}


void eap_int_to_bytes_be(uint16_t value, uint8_t *out) 
{
    out[0] = (value >> 8) & 0xFF;
    out[1] = value & 0xFF;
}

void eap_pad_zeros(const uint8_t *input, size_t input_len, uint8_t *output, size_t padded_len) 
{
    memset(output, 0, padded_len);
    if (input_len > padded_len) input_len = padded_len;
    memcpy(output + (padded_len - input_len), input, input_len);
}

void eap_aka_encode_packet(eap_aka_packet_t *packet, uint8_t *output)
{
    output[0] = packet->code;
    output[1] = packet->identifier;
    output[2] = (packet->length >> 8) & 0xFF;
    output[3] = packet->length & 0xFF;
    if(packet->code==EAP_CODE_REQUEST){
        output[4] = packet->type;
        output[5] = packet->sub_type;
        output[6] = 0x00;
        output[7] = 0x00;

        size_t payload_len = packet->length - EAP_AKA_REQUEST_MIN_LENGTH;
        memcpy(output + EAP_AKA_REQUEST_MIN_LENGTH, packet->data, payload_len);

    }
}


size_t eap_aka_decode_attribute(EapAkaAttributeType eap_aka_attribute_type, uint8_t *input, size_t input_len, uint8_t *output)
{   
    //start from 8
    size_t i = 8; 

    while (i + 2 <= input_len) {
        uint8_t type = input[i];
        size_t attr_total_len = 0;

        if(type==EAP_AKA_ATTRIBUTE_AT_PUB_HYBRID){
            //uint8_t len_units = input[i + 1];
            //uint16_t len_units = 281;
            attr_total_len = 1124;
        }
        else{
            uint8_t len_units = input[i + 1];
            attr_total_len = len_units * 4;
        }
        

        //if (attr_total_len < 4 || i + attr_total_len > input_len)
        //    break;  // malformed or truncated

        if (type == eap_aka_attribute_type) {
            size_t value_len = 0;
            const uint8_t *value_ptr = NULL;

            switch (type) {
                case EAP_AKA_ATTRIBUTE_AT_RES: 
                    if (attr_total_len < 4) return 0;
                    uint16_t bit_len = (input[i + 2] << 8) | input[i + 3];
                    value_len = bit_len / 8;
                    if (value_len > attr_total_len - 4) return 0;
                    value_ptr = input + i + 4;
                    break;
                case EAP_AKA_ATTRIBUTE_AT_MAC:
                    value_len = 16;
                    value_ptr = input + i + 4;
                    break;
                case EAP_AKA_ATTRIBUTE_AT_PUB_ECDHE:
                    value_len = 32;
                    value_ptr = input + i + 4;
                    break;
                case EAP_AKA_ATTRIBUTE_AT_PUB_HYBRID:
                    value_len = 1120;
                    value_ptr = input + i + 4;
                    break;
                default:
                    return 0;
            }

            // Fill output
            memcpy(output, value_ptr, value_len);
            return value_len;
        }

        i += attr_total_len;
    }
    
    return 0;
}


void eap_aka_clean_mac(EapAkaAttributeType eap_aka_attribute_type ,uint8_t *input, size_t input_len, uint8_t *output)
{

    memcpy(output, input, input_len);
    //start from 8
    size_t i = 8; 

    while (i + 2 <= input_len) {
        // uint8_t type = input[i];
        // uint8_t len_units = input[i + 1];
        // size_t attr_total_len = len_units * 4;

        uint8_t type = input[i];
        size_t attr_total_len = 0;

        if(type==EAP_AKA_ATTRIBUTE_AT_PUB_HYBRID){
            //uint8_t len_units = input[i + 1];
            //uint16_t len_units = 281;
            attr_total_len = 1124;
        }
        else{
            uint8_t len_units = input[i + 1];
            attr_total_len = len_units * 4;
        }

        if (attr_total_len < 4 || i + attr_total_len > input_len)
            break;  // malformed or truncated

        if (type == EAP_AKA_ATTRIBUTE_AT_MAC) {
            size_t value_len = 0;
            const uint8_t *value_ptr = NULL;

            value_len = 16;
            value_ptr = input + i + 4;

            // Fill output
            size_t offset = value_ptr - input;
            memset(output + offset ,0x00, value_len);
            return;
        }

        i += attr_total_len;
    }
}

void eap_prf_prime(uint8_t *key, size_t key_len, uint8_t *input, size_t input_len, uint8_t *output, size_t output_len)
{
    ogs_assert(key);
    ogs_assert(input);

    int i = 0;
    int round = output_len / 32 + 1;  
    uint8_t *s = NULL;

    uint8_t **T = calloc(round, sizeof(uint8_t *));
   
    for (i = 0; i < round ; i++){
        int s_len = (i == 0 ? 0 : 32) + input_len + 1;

        s = ogs_calloc(1, s_len);
        
        if(!s){
            ogs_free(s);
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
        
        T[i] = malloc(EAP_SHA256_BLOCK_SIZE);
        
        eap_hmac_sha256(key, key_len , s, s_len,  T[i], 32);

        ogs_free(s);
        
    } 

    size_t total_len = round * 32;
    uint8_t result[total_len];

    for (i = 0; i < round; i++) {
        memcpy(result + i * 32, T[i], 32);
        free(T[i]);
    }

    memcpy(output, result, output_len);
}


/* HMAC-SHA-256 functions */

void eap_hmac_sha256_init(ogs_hmac_sha256_ctx *ctx, const uint8_t *key,
    uint32_t key_size)
{
    uint32_t fill;
    uint32_t num;

    uint8_t key_temp[EAP_SHA256_BLOCK_SIZE];
    int i;

    if (key_size > EAP_SHA256_BLOCK_SIZE){
        num = EAP_SHA256_DIGEST_SIZE;
        ogs_sha256(key, key_size, key_temp);
    } else { /* key_size <= EAP_SHA256_BLOCK_SIZE */
        memcpy(key_temp, key, sizeof(key_temp));
        num = key_size;
    }
    fill = EAP_SHA256_BLOCK_SIZE - num;

    memset(ctx->block_ipad + num, 0x36, fill);
    memset(ctx->block_opad + num, 0x5c, fill);
    //}

    for (i = 0; i < num; i++) {
        ctx->block_ipad[i] = key_temp[i] ^ 0x36;
        ctx->block_opad[i] = key_temp[i] ^ 0x5c;
    }

    ogs_sha256_init(&ctx->ctx_inside);
    ogs_sha256_update(&ctx->ctx_inside, ctx->block_ipad, EAP_SHA256_BLOCK_SIZE);

    ogs_sha256_init(&ctx->ctx_outside);
    ogs_sha256_update(&ctx->ctx_outside, ctx->block_opad,
        EAP_SHA256_BLOCK_SIZE);

    /* for hmac_reinit */
    memcpy(&ctx->ctx_inside_reinit, &ctx->ctx_inside,
    sizeof(ogs_sha256_ctx));
    memcpy(&ctx->ctx_outside_reinit, &ctx->ctx_outside,
    sizeof(ogs_sha256_ctx));
}

void eap_hmac_sha256_reinit(ogs_hmac_sha256_ctx *ctx)
{
    memcpy(&ctx->ctx_inside, &ctx->ctx_inside_reinit,
    sizeof(ogs_sha256_ctx));
    memcpy(&ctx->ctx_outside, &ctx->ctx_outside_reinit,
    sizeof(ogs_sha256_ctx));
}

void eap_hmac_sha256_update(ogs_hmac_sha256_ctx *ctx, const uint8_t *message,
                        uint32_t message_len)
{
    ogs_sha256_update(&ctx->ctx_inside, message, message_len);
}

void eap_hmac_sha256_final(ogs_hmac_sha256_ctx *ctx, uint8_t *mac,
                        uint32_t mac_size)
{
    uint8_t digest_inside[EAP_SHA256_DIGEST_SIZE];
    uint8_t mac_temp[EAP_SHA256_DIGEST_SIZE];

    ogs_sha256_final(&ctx->ctx_inside, digest_inside);
    ogs_sha256_update(&ctx->ctx_outside, digest_inside, EAP_SHA256_DIGEST_SIZE);
    ogs_sha256_final(&ctx->ctx_outside, mac_temp);
    memcpy(mac, mac_temp, mac_size);
}

void eap_hmac_sha256(const uint8_t *key, uint32_t key_size,
                const uint8_t *message, uint32_t message_len,
                uint8_t *mac, uint32_t mac_size)
{
    ogs_hmac_sha256_ctx ctx;

    eap_hmac_sha256_init(&ctx, key, key_size);
    eap_hmac_sha256_update(&ctx, message, message_len);
    eap_hmac_sha256_final(&ctx, mac, mac_size);
}

void eap_aka_prime_fs_key_generation(uint8_t *priv_key_ecdhe, uint8_t *pub_key_ecdhe){

    // generate random private key
    priv_key_ecdhe[0] &= 248;
    priv_key_ecdhe[31] &= 127;
    priv_key_ecdhe[31] |= 64;

    static const uint8_t curve25519_basepoint[32] = {9};
    
    curve25519_donna(pub_key_ecdhe, priv_key_ecdhe, curve25519_basepoint);
}

void eap_aka_prime_fs_generate_shared_key(uint8_t *shared_key, uint8_t *priv_key_ecdhe, uint8_t *pub_key_ecdhe){
    curve25519_donna(shared_key, priv_key_ecdhe, pub_key_ecdhe);
}

void eap_aka_prime_hpqc_xwing_key_generation(uint8_t *decapsulation_key, uint8_t *encapsulation_key){
    uint8_t expanded[96];
    uint8_t sk[32];

    OQS_randombytes(sk, 32);

    // randomize sk
    //sk[0] &= 248;
    //sk[31] &= 127;
    //sk[31] |= 64;
    
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
    curve25519_donna(pk_X, sk_X, x25519_base);

    memcpy(decapsulation_key, sk, 32);
    memcpy(encapsulation_key, public_key, 1184);
    memcpy(encapsulation_key+1184, pk_X , 32);
}

void eap_aka_prime_hpqc_xwing_decapsulate(uint8_t *shared_key, uint8_t *ct_xwing, uint8_t *sk_xwing){
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

     curve25519_donna(pk_X, sk_X, x25519_base);

     // we have sk_M, pk_M, sk_X, pk_X

     OQS_KEM_ml_kem_768_decaps(ss_M, ct_M, sk_M);

     curve25519_donna(ss_X, sk_X, ct_X);

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

void eap_aka_prime_generate_mk(uint8_t *ik_prime,uint8_t *ck_prime, char *input_supi, uint8_t *mk){

    size_t key_len = 32;

    uint8_t key_prf[key_len];
    memcpy(key_prf, ik_prime, 16);
    memcpy(key_prf+16, ck_prime, 16);

    const char *prefix = "EAP-AKA'";
    char *supi = ogs_id_get_value(input_supi);
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

    eap_prf_prime(key_prf, key_len, input, input_len, mk, mk_len);
}


void eap_aka_prime_generate_mk_shared(uint8_t *ik_prime,uint8_t *ck_prime,uint8_t *shared_key, char *input_supi, uint8_t *mk_shared){
    size_t key_len = 64;

    uint8_t key_prf[key_len];
    memcpy(key_prf, ik_prime, 16);
    memcpy(key_prf+16, ck_prime, 16);
    memcpy(key_prf+32, shared_key, 32);

    const char *prefix = "EAP-AKA' FS";
    char *supi = ogs_id_get_value(input_supi);
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

    eap_prf_prime(key_prf, key_len, input, input_len, mk_shared, mk_shared_len);
}

