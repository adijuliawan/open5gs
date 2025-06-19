#ifndef KMU_EAP_H
#define KMU_EAP_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KMU_EAP_AKA_ATTRIBUTE_AT_RAND_LENGTH                    20
#define KMU_EAP_AKA_ATTRIBUTE_AT_AUTN_LENGTH                    20
#define KMU_EAP_AKA_ATTRIBUTE_AT_RES_LENGTH                     20
#define KMU_EAP_AKA_ATTRIBUTE_AT_AUTS_LENGTH                    20
#define KMU_EAP_AKA_ATTRIBUTE_AT_MAC_LENGTH                     20
#define KMU_EAP_AKA_ATTRIBUTE_AT_KDF_LENGTH                     4
#define KMU_EAP_AKA_ATTRIBUTE_AT_KDF_FS_LENGTH                  4
#define KMU_EAP_AKA_ATTRIBUTE_AT_PUB_ECDHE_LENGTH               36
#define KMU_EAP_AKA_ATTRIBUTE_AT_PUB_HYBRID_LENGTH              1220
#define KMU_EAP_AKA_ATTRIBUTE_AT_PUB_KEM_LENGTH                 1188
#define KMU_EAP_AKA_ATTRIBUTE_AT_KEM_CT_LENGTH                  1092

#define KMU_MAX_EAP_PAYLOAD_LEN                                 1900
/**
 * EAP Code 
 **/

typedef enum
{
    KMU_EAP_CODE_REQUEST  = 1, 
    KMU_EAP_CODE_RESPONSE = 2, 
    KMU_EAP_CODE_SUCCESS  = 3, 
    KMU_EAP_CODE_FAILURE  = 4  
} KMUEapCode;

 /**
  * EAP method types
  **/
  
typedef enum
{
    KMU_EAP_METHOD_TYPE_NONE          = 0,  ///<None
    KMU_EAP_METHOD_TYPE_IDENTITY      = 1,  ///<Identity
    KMU_EAP_METHOD_TYPE_NOTIFICATION  = 2,  ///<Notification
    KMU_EAP_METHOD_TYPE_NAK           = 3,  ///<Legacy Nak
    KMU_EAP_METHOD_TYPE_MD5_CHALLENGE = 4,  ///<MD5-Challenge
    KMU_EAP_METHOD_TYPE_OTP           = 5,  ///<One-Time Password (OTP)
    KMU_EAP_METHOD_TYPE_GTC           = 6,  ///<Generic Token Card (GTC)
    KMU_EAP_METHOD_TYPE_TLS           = 13, ///<EAP-TLS
    KMU_EAP_METHOD_TYPE_TTLS          = 21, ///<EAP-TTLS
    KMU_EAP_METHOD_TYPE_AKA           = 23, // <EAP-AKA
    KMU_EAP_METHOD_TYPE_PEAP          = 25, ///<PEAP
    KMU_EAP_METHOD_TYPE_MSCHAP_V2     = 29, ///<EAP-MSCHAP-V2
    KMU_EAP_METHOD_TYPE_AKA_PRIME     = 50, // <EAP-AKA-PRIME
    KMU_EAP_METHOD_TYPE_EXPANDED_NAK  = 254 ///<Expanded NAK
} KMUEapMethodType;


 /**
  * EAP AKA subtypes
  **/

typedef enum 
{
    KMU_EAP_AKA_SUBTYPE_AKA_CHALLENGE                              = 1,
    KMU_EAP_AKA_SUBTYPE_AKA_AUTHENTICATION_REJECT                  = 2,
    KMU_EAP_AKA_SUBTYPE_AKA_SYNCHRONIZATION_FAILURE                = 4,
    KMU_EAP_AKA_SUBTYPE_AKA_IDENTITY                               = 5,
    KMU_EAP_AKA_SUBTYPE_AKA_NOTIFICATION                           = 12,
    KMU_EAP_AKA_SUBTYPE_AKA_REAUTHENTICATION                       = 13,
    KMU_EAP_AKA_SUBTYPE_AKA_CLIENT_ERROR                           = 14

} KMUEapAkaSubType;


 /**
  * EAP AKA attribute 
  **/

typedef enum {
    KMU_EAP_AKA_ATTRIBUTE_AT_RAND                       = 1,
    KMU_EAP_AKA_ATTRIBUTE_AT_AUTN                       = 2,
    KMU_EAP_AKA_ATTRIBUTE_AT_RES                        = 3,
    KMU_EAP_AKA_ATTRIBUTE_AT_AUTS                       = 4,
    KMU_EAP_AKA_ATTRIBUTE_AT_PADDING                    = 6,
    KMU_EAP_AKA_ATTRIBUTE_AT_NONCE_MT                   = 7,
    KMU_EAP_AKA_ATTRIBUTE_AT_PERMANENT_ID_REQ           = 10,
    KMU_EAP_AKA_ATTRIBUTE_AT_MAC                        = 11,
    KMU_EAP_AKA_ATTRIBUTE_AT_NOTIFICATION               = 12,
    KMU_EAP_AKA_ATTRIBUTE_AT_ANY_ID_REQ                 = 13,
    KMU_EAP_AKA_ATTRIBUTE_AT_IDENTITY                   = 14,
    KMU_EAP_AKA_ATTRIBUTE_AT_VERSION_LIST               = 15,
    KMU_EAP_AKA_ATTRIBUTE_AT_SELECTED_VERSION           = 16,
    KMU_EAP_AKA_ATTRIBUTE_AT_FULLAUTH_ID_REQ            = 17,
    KMU_EAP_AKA_ATTRIBUTE_AT_COUNTER                    = 19,
    KMU_EAP_AKA_ATTRIBUTE_AT_COUNTER_TOO_SMALL          = 20,
    KMU_EAP_AKA_ATTRIBUTE_AT_NONCE_S                    = 21,
    KMU_EAP_AKA_ATTRIBUTE_AT_CLIENT_ERROR_CODE          = 22,
    KMU_EAP_AKA_ATTRIBUTE_AT_KDF_INPUT                  = 23,
    KMU_EAP_AKA_ATTRIBUTE_AT_KDF                        = 24,
    KMU_EAP_AKA_ATTRIBUTE_AT_IV                         = 129,
    KMU_EAP_AKA_ATTRIBUTE_AT_ENCR_DATA                  = 130,
    KMU_EAP_AKA_ATTRIBUTE_AT_NEXT_PSEUDONYM             = 132,
    KMU_EAP_AKA_ATTRIBUTE_AT_NEXT_REAUTH_ID             = 133,
    KMU_EAP_AKA_ATTRIBUTE_AT_CHECKCODE                  = 134,
    KMU_EAP_AKA_ATTRIBUTE_AT_RESULT_IND                 = 135,
    KMU_EAP_AKA_ATTRIBUTE_AT_BIDDING                    = 136,
    KMU_EAP_AKA_ATTRIBUTE_AT_PUB_ECDHE                  = 152,
    KMU_EAP_AKA_ATTRIBUTE_AT_KDF_FS                     = 153,
    KMU_EAP_AKA_ATTRIBUTE_AT_PUB_HYBRID                 = 154,
    KMU_EAP_AKA_ATTRIBUTE_AT_PUB_KEM                    = 155,
    KMU_EAP_AKA_ATTRIBUTE_AT_KEM_CT                     = 156

} KMUEapAkaAttributeType;

/**
  * EAP packet
  **/
  
typedef struct kmu_eap_packet
{
    uint8_t code;       //0
    uint8_t identifier; //1
    uint16_t length;    //2-3
    uint8_t data[];     //4
} kmu_eap_packet_t;

/**
 * EAP request
 **/

typedef struct kmu_eap_request
{
    uint8_t code;       //0
    uint8_t identifier; //1
    uint16_t length;    //2-3
    uint8_t type;       //4
    uint8_t data[];     //5
} kmu_eap_request_t;

/**
 * EAP response
 **/

typedef struct kmu_eap_response
{
    uint8_t code;       //0
    uint8_t identifier; //1
    uint16_t length;    //2-3
    uint8_t type;       //4
    uint8_t data[];     //5
} kmu_eap_response_t;

/**
 * EAP-AKA packet 
 **/

typedef struct kmu_eap_aka_packet
{
    uint8_t code;       //0
    uint8_t identifier; //1
    uint16_t length;    //2-3
    uint8_t type;       //4
    uint8_t sub_type;    // 5
    uint16_t reserved;  // 6-7
    uint8_t data[];     // 8
} kmu_eap_aka_packet_t;

typedef struct kmu_eap_aka_attribute_data 
{
    uint8_t type;
    uint16_t length; // length of value in bytes, not length in attribute
    uint8_t value[];
} kmu_eap_aka_attribute_data_t;

// MAX EAP PAYLOAD 7-1503 

void kmu_eap_aka_build_request(kmu_eap_aka_packet_t *packet, KMUEapAkaSubType sub_type, size_t data_len, uint8_t *data);

void kmu_eap_aka_parse_response(kmu_eap_aka_packet_t *packet, uint8_t *input);

void kmu_eap_aka_build_success(kmu_eap_aka_packet_t *packet);

void kmu_eap_aka_build_failure(kmu_eap_aka_packet_t *packet);

// convert from struct to hexadecimal
void kmu_eap_aka_encode_packet(kmu_eap_aka_packet_t *packet, uint8_t *output);

size_t kmu_eap_aka_encode_attribute(KMUEapAkaAttributeType eap_aka_attribute_type, const void *input, size_t input_len, uint8_t *output);

size_t kmu_eap_aka_decode_attribute(KMUEapAkaAttributeType eap_aka_attribute_type, uint8_t *input, size_t input_len, uint8_t *output);

void kmu_eap_aka_clean_mac(KMUEapAkaAttributeType eap_aka_attribute_type ,uint8_t *input, size_t input_len, uint8_t *output);

uint8_t kmu_eap_next_id(uint8_t identifier);

void kmu_eap_int_to_bytes_be(uint16_t value, uint8_t *out);

void kmu_eap_pad_zeros(const uint8_t *input, size_t input_len, uint8_t *output, size_t padded_len);


#ifdef __cplusplus
}
#endif

#endif