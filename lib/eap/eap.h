#ifndef OGS_EAP_H
#define OGS_EAP_H


#include <stddef.h>
#include <stdint.h>
#include "../crypt/ogs-crypt.h"

#ifdef __cplusplus
extern "C" {
#endif


#define EAP_AKA_ATTRIBUTE_AT_RAND_LENGTH                    20
#define EAP_AKA_ATTRIBUTE_AT_AUTN_LENGTH                    20
#define EAP_AKA_ATTRIBUTE_AT_RES_LENGTH                     20
#define EAP_AKA_ATTRIBUTE_AT_AUTS_LENGTH                    20
#define EAP_AKA_ATTRIBUTE_AT_MAC_LENGTH                     20
#define EAP_AKA_ATTRIBUTE_AT_KDF_LENGTH                     4
#define EAP_AKA_ATTRIBUTE_AT_KDF_FS_LENGTH                  4
#define EAP_AKA_ATTRIBUTE_AT_PUB_ECDHE_LENGTH               36
#define EAP_AKA_ATTRIBUTE_AT_PUB_HYBRID_LENGTH              1220
#define EAP_AKA_ATTRIBUTE_AT_PUB_KEM_LENGTH                 1188
#define EAP_AKA_ATTRIBUTE_AT_KEM_CT_LENGTH                  1092

#define EAP_SHA256_BLOCK_SIZE  ( 512 / 8)
#define EAP_SHA256_DIGEST_SIZE ( 256 / 8)

/*
EAP Packet (RFC 3748)

EAP Request and Response
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Code      |  Identifier   |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |  Type-Data ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-


EAP Success and Failure 
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Code      |  Identifier   |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+



EAP AKA Request and Response (RFC 4187)
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Code      |  Identifier   |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |    Subtype    |           Reserved            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Attribute ...
+-+-+-+-+-+-+-+-+-+-


EAP AKA Attribute
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Attribute Type |    Length     | Value...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/


/**
 * EAP Code 
 **/

typedef enum
{
    EAP_CODE_REQUEST  = 1, 
    EAP_CODE_RESPONSE = 2, 
    EAP_CODE_SUCCESS  = 3, 
    EAP_CODE_FAILURE  = 4  
} EapCode;

 /**
  * EAP method types
  **/
  
typedef enum
{
    EAP_METHOD_TYPE_NONE          = 0,  ///<None
    EAP_METHOD_TYPE_IDENTITY      = 1,  ///<Identity
    EAP_METHOD_TYPE_NOTIFICATION  = 2,  ///<Notification
    EAP_METHOD_TYPE_NAK           = 3,  ///<Legacy Nak
    EAP_METHOD_TYPE_MD5_CHALLENGE = 4,  ///<MD5-Challenge
    EAP_METHOD_TYPE_OTP           = 5,  ///<One-Time Password (OTP)
    EAP_METHOD_TYPE_GTC           = 6,  ///<Generic Token Card (GTC)
    EAP_METHOD_TYPE_TLS           = 13, ///<EAP-TLS
    EAP_METHOD_TYPE_TTLS          = 21, ///<EAP-TTLS
    EAP_METHOD_TYPE_AKA           = 23, // <EAP-AKA
    EAP_METHOD_TYPE_PEAP          = 25, ///<PEAP
    EAP_METHOD_TYPE_MSCHAP_V2     = 29, ///<EAP-MSCHAP-V2
    EAP_METHOD_TYPE_AKA_PRIME     = 50, // <EAP-AKA-PRIME
    EAP_METHOD_TYPE_EXPANDED_NAK  = 254 ///<Expanded NAK
} EapMethodType;


 /**
  * EAP AKA subtypes
  **/

typedef enum 
{
    EAP_AKA_SUBTYPE_AKA_CHALLENGE                              = 1,
    EAP_AKA_SUBTYPE_AKA_AUTHENTICATION_REJECT                  = 2,
    EAP_AKA_SUBTYPE_AKA_SYNCHRONIZATION_FAILURE                = 4,
    EAP_AKA_SUBTYPE_AKA_IDENTITY                               = 5,
    EAP_AKA_SUBTYPE_AKA_NOTIFICATION                           = 12,
    EAP_AKA_SUBTYPE_AKA_REAUTHENTICATION                       = 13,
    EAP_AKA_SUBTYPE_AKA_CLIENT_ERROR                           = 14

} EapAkaSubType;


 /**
  * EAP AKA attribute 
  **/

typedef enum {
    EAP_AKA_ATTRIBUTE_AT_RAND                       = 1,
    EAP_AKA_ATTRIBUTE_AT_AUTN                       = 2,
    EAP_AKA_ATTRIBUTE_AT_RES                        = 3,
    EAP_AKA_ATTRIBUTE_AT_AUTS                       = 4,
    EAP_AKA_ATTRIBUTE_AT_PADDING                    = 6,
    EAP_AKA_ATTRIBUTE_AT_NONCE_MT                   = 7,
    EAP_AKA_ATTRIBUTE_AT_PERMANENT_ID_REQ           = 10,
    EAP_AKA_ATTRIBUTE_AT_MAC                        = 11,
    EAP_AKA_ATTRIBUTE_AT_NOTIFICATION               = 12,
    EAP_AKA_ATTRIBUTE_AT_ANY_ID_REQ                 = 13,
    EAP_AKA_ATTRIBUTE_AT_IDENTITY                   = 14,
    EAP_AKA_ATTRIBUTE_AT_VERSION_LIST               = 15,
    EAP_AKA_ATTRIBUTE_AT_SELECTED_VERSION           = 16,
    EAP_AKA_ATTRIBUTE_AT_FULLAUTH_ID_REQ            = 17,
    EAP_AKA_ATTRIBUTE_AT_COUNTER                    = 19,
    EAP_AKA_ATTRIBUTE_AT_COUNTER_TOO_SMALL          = 20,
    EAP_AKA_ATTRIBUTE_AT_NONCE_S                    = 21,
    EAP_AKA_ATTRIBUTE_AT_CLIENT_ERROR_CODE          = 22,
    EAP_AKA_ATTRIBUTE_AT_KDF_INPUT                  = 23,
    EAP_AKA_ATTRIBUTE_AT_KDF                        = 24,
    EAP_AKA_ATTRIBUTE_AT_IV                         = 129,
    EAP_AKA_ATTRIBUTE_AT_ENCR_DATA                  = 130,
    EAP_AKA_ATTRIBUTE_AT_NEXT_PSEUDONYM             = 132,
    EAP_AKA_ATTRIBUTE_AT_NEXT_REAUTH_ID             = 133,
    EAP_AKA_ATTRIBUTE_AT_CHECKCODE                  = 134,
    EAP_AKA_ATTRIBUTE_AT_RESULT_IND                 = 135,
    EAP_AKA_ATTRIBUTE_AT_BIDDING                    = 136,
    EAP_AKA_ATTRIBUTE_AT_PUB_ECDHE                  = 152,
    EAP_AKA_ATTRIBUTE_AT_KDF_FS                     = 153,
    EAP_AKA_ATTRIBUTE_AT_PUB_HYBRID                 = 154,
    EAP_AKA_ATTRIBUTE_AT_PUB_KEM                    = 155,
    EAP_AKA_ATTRIBUTE_AT_KEM_CT                     = 156

} EapAkaAttributeType;



/**
  * EAP packet
  **/
  
typedef struct eap_packet
{
    uint8_t code;       //0
    uint8_t identifier; //1
    uint16_t length;    //2-3
    uint8_t data[];     //4
} eap_pakcet_t;

/**
 * EAP request
 **/

typedef struct eap_request
{
    uint8_t code;       //0
    uint8_t identifier; //1
    uint16_t length;    //2-3
    uint8_t type;       //4
    uint8_t data[];     //5
} eap_request_t;
   
   
/**
 * EAP response
 **/

typedef struct eap_response
{
    uint8_t code;       //0
    uint8_t identifier; //1
    uint16_t length;    //2-3
    uint8_t type;       //4
    uint8_t data[];     //5
} eap_response_t;

/**
 * EAP-AKA packet 
 **/

typedef struct eap_aka_packet
{
    uint8_t code;       //0
    uint8_t identifier; //1
    uint16_t length;    //2-3
    uint8_t type;       //4
    uint8_t sub_type;    // 5
    uint16_t reserved;  // 6-7
    uint8_t data[];     // 8
} eap_aka_packet_t;


typedef struct eap_aka_attribute_data 
{
    uint8_t type;
    uint16_t length; // length of value in bytes, not length in attribute
    uint8_t value[];
} eap_aka_attribute_data_t;

// create EAP-AKA Request 
/**
 * Input : eap_aka_packet, EapAka Attribute
*/

// MAX EAP PAYLOAD 7-1503 

void eap_aka_build_request(eap_aka_packet_t *packet, EapAkaSubType sub_type, size_t data_len, uint8_t *data);

void eap_aka_parse_response(eap_aka_packet_t *packet, uint8_t *input);

void eap_aka_build_success(eap_aka_packet_t *packet);

void eap_aka_build_failure(eap_aka_packet_t *packet);

// convert from struct to hexadecimal
void eap_aka_encode_packet(eap_aka_packet_t *packet, uint8_t *output);

size_t eap_aka_encode_attribute(EapAkaAttributeType eap_aka_attribute_type, const void *input, size_t input_len, uint8_t *output);

size_t eap_aka_decode_attribute(EapAkaAttributeType eap_aka_attribute_type, uint8_t *input, size_t input_len, uint8_t *output);

void eap_aka_clean_mac(EapAkaAttributeType eap_aka_attribute_type ,uint8_t *input, size_t input_len, uint8_t *output);

uint8_t eap_next_id(uint8_t id);

void eap_int_to_bytes_be(uint16_t value, uint8_t *out);

void eap_pad_zeros(const uint8_t *input, size_t input_len, uint8_t *output, size_t padded_len);

void eap_prf_prime(uint8_t *key, size_t key_len, uint8_t *input, size_t input_len, uint8_t *output, size_t output_len);



void eap_hmac_sha256_init(ogs_hmac_sha256_ctx *ctx, const uint8_t *key,
    uint32_t key_size);
void eap_hmac_sha256_reinit(ogs_hmac_sha256_ctx *ctx);
void eap_hmac_sha256_update(ogs_hmac_sha256_ctx *ctx, const uint8_t *message,
      uint32_t message_len);
void eap_hmac_sha256_final(ogs_hmac_sha256_ctx *ctx, uint8_t *mac,
     uint32_t mac_size);
void eap_hmac_sha256(const uint8_t *key, uint32_t key_size,
    const uint8_t *message, uint32_t message_len,
    uint8_t *mac, uint32_t mac_size);


void eap_aka_prime_generate_mk(uint8_t *ik_prime,uint8_t *ck_prime, char *input_supi, uint8_t *mk);
void eap_aka_prime_generate_mk_shared(uint8_t *ik_prime,uint8_t *ck_prime,uint8_t *shared_key, char *input_supi, uint8_t *mk_shared);
void eap_aka_prime_generate_mk_pq_shared(uint8_t *ik_prime,uint8_t *ck_prime,uint8_t *shared_key, char *input_supi, uint8_t *input_ct, uint8_t *mk_shared);

// FS Extension
void eap_aka_prime_fs_key_generation(uint8_t *priv_key_ecdhe, uint8_t *pub_key_ecdhe); 
void eap_aka_prime_fs_generate_shared_key(uint8_t *shared_key, uint8_t *priv_key_ecdhe, uint8_t *pub_key_ecdhe); 

// HPQC Extension
void eap_aka_prime_hpqc_xwing_key_generation(uint8_t *decapsulation_key, uint8_t *encapsulation_key); 
void eap_aka_prime_hpqc_xwing_decapsulate(uint8_t *shared_key, uint8_t *ct_xwing, uint8_t *sk_xwing); 

//PQ KEM Extension
void eap_aka_prime_pq_kem_key_generation(uint8_t *public_key_pq_kem,uint8_t *secret_key_pq_kem);
void eap_aka_prime_pq_kem_decapsulate(uint8_t *shared_key, uint8_t *ct, uint8_t *sk);






#ifdef __cplusplus
}
#endif

#endif