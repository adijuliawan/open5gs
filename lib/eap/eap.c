#include "eap.h"
#include <stdio.h>
#include "../core/ogs-core.h"

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


void eap_aka_decode_attribute(EapAkaAttributeType eap_aka_attribute_type, uint8_t *input, size_t input_len, uint8_t *output)
{   
    //start from 8
    size_t i = 8; 

    while (i + 2 <= input_len) {
        uint8_t type = input[i];
        uint8_t len_units = input[i + 1];
        size_t attr_total_len = len_units * 4;

        if (attr_total_len < 4 || i + attr_total_len > input_len)
            break;  // malformed or truncated

        if (type == eap_aka_attribute_type) {
            size_t value_len = 0;
            const uint8_t *value_ptr = NULL;

            switch (type) {
                case EAP_AKA_ATTRIBUTE_AT_RES: 
                    if (attr_total_len < 4) return;
                    uint16_t bit_len = (input[i + 2] << 8) | input[i + 3];
                    value_len = bit_len / 8;
                    if (value_len > attr_total_len - 4) return;
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
                default:
                    return;
            }

            // Fill output
            memcpy(output, value_ptr, value_len);
            return;
        }

        i += attr_total_len;
    }
    
}

void eap_aka_clean_mac(EapAkaAttributeType eap_aka_attribute_type ,uint8_t *input, size_t input_len, uint8_t *output)
{

    memcpy(output, input, input_len);
    //start from 8
    size_t i = 8; 

    while (i + 2 <= input_len) {
        uint8_t type = input[i];
        uint8_t len_units = input[i + 1];
        size_t attr_total_len = len_units * 4;

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





