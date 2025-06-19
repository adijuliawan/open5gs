#include "kmu_eap.h"


uint8_t identifier = 100;
const uint16_t KMU_EAP_AKA_REQUEST_MIN_LENGTH = 8;

uint8_t kmu_eap_next_id(uint8_t identifier)
{
    identifier = (identifier + 1) % 256;
    return identifier;
}

void kmu_eap_aka_build_request(kmu_eap_aka_packet_t *packet, KMUEapAkaSubType sub_type, size_t data_len, uint8_t *data)
{
    packet->code = KMU_EAP_CODE_REQUEST;
    packet->identifier = kmu_eap_next_id(identifier);
    packet->length = KMU_EAP_AKA_REQUEST_MIN_LENGTH + data_len;
    packet->type = KMU_EAP_METHOD_TYPE_AKA_PRIME;
    packet->sub_type = sub_type;
    memcpy(packet->data, data, data_len);
}

void kmu_eap_aka_parse_response(kmu_eap_aka_packet_t *packet, uint8_t *input)
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

void kmu_eap_aka_build_success(kmu_eap_aka_packet_t *packet)
{
    packet->code = KMU_EAP_CODE_SUCCESS;
    packet->identifier = kmu_eap_next_id(identifier);
    packet->length = 4;
}

void kmu_eap_aka_build_failure(kmu_eap_aka_packet_t *packet)
{
    packet->code = KMU_EAP_CODE_FAILURE;
    packet->identifier = kmu_eap_next_id(identifier);
    packet->length = 4;
}

size_t kmu_eap_aka_encode_attribute(KMUEapAkaAttributeType kmu_eap_aka_attribute_type, const void *input, size_t input_len, uint8_t *output)
{
    switch(kmu_eap_aka_attribute_type){
        case KMU_EAP_AKA_ATTRIBUTE_AT_RAND:
            output[0] = KMU_EAP_AKA_ATTRIBUTE_AT_RAND;
            output[1] = 5;
            output[2] = 0x00;
            output[3] = 0x00;
            memcpy(output+4, input, input_len);
            return 20;
            break;
        
        case KMU_EAP_AKA_ATTRIBUTE_AT_AUTN:
            output[0] = KMU_EAP_AKA_ATTRIBUTE_AT_AUTN;
            output[1] = 5;
            output[2] = 0x00;
            output[3] = 0x00;
            memcpy(output+4, input, input_len);
            return 20;
            break;
        
        case KMU_EAP_AKA_ATTRIBUTE_AT_MAC:
            output[0] = KMU_EAP_AKA_ATTRIBUTE_AT_MAC; 
            output[1] = 5;
            output[2] = output[3] = 0x00;
            memset(output + 4, 0x00, input_len);
            return 20;
            break;

        case KMU_EAP_AKA_ATTRIBUTE_AT_KDF:
            output[0] = KMU_EAP_AKA_ATTRIBUTE_AT_KDF;
            output[1] = 1;
            output[2] = 0x00;
            output[3] = 0x01;
            return 4;
            break;

        case KMU_EAP_AKA_ATTRIBUTE_AT_KDF_INPUT:
            
            // Total padded length (round up to multiple of 4)
            size_t padded_len = ((input_len + 3) / 4) * 4;
            size_t length_field = (padded_len / 4) + 1;

            output[0] = KMU_EAP_AKA_ATTRIBUTE_AT_KDF_INPUT;
            output[1] = (uint8_t)length_field;
            kmu_eap_int_to_bytes_be((uint16_t)input_len, output + 2);

            // Apply LEFT padding (zeros before data)
            memset(output + 4, 0x00, padded_len);
            if (input_len > padded_len) input_len = padded_len;
            memcpy(output + 4 + (padded_len - input_len), input, input_len);

            return length_field * 4;
            break;
        
        case KMU_EAP_AKA_ATTRIBUTE_AT_PUB_ECDHE:
            // X25519 : 32 bytes + 1 + 1 = 34 + 2 (padding) = 36/4 = 9(length)
            // P256-1 : 33 bytes + 1 + 1 = 35 + 1 (padding) = 36/4 = 9(length)
            output[0] = KMU_EAP_AKA_ATTRIBUTE_AT_PUB_ECDHE;
            output[1] = KMU_EAP_AKA_ATTRIBUTE_AT_PUB_ECDHE_LENGTH/4;
            memset(output + 2, 0x00, 34);
            memcpy(output + KMU_EAP_AKA_ATTRIBUTE_AT_PUB_ECDHE_LENGTH - input_len, input, input_len);
            return KMU_EAP_AKA_ATTRIBUTE_AT_PUB_ECDHE_LENGTH;
            break;
        
        case KMU_EAP_AKA_ATTRIBUTE_AT_PUB_HYBRID:
            // X-Wing : 1216 bytes + 2 + 1 = 1219 + 1 (padding) = 1220/4 = 305(length)
            output[0] = KMU_EAP_AKA_ATTRIBUTE_AT_PUB_HYBRID;
            size_t length_pub_hybrid = KMU_EAP_AKA_ATTRIBUTE_AT_PUB_HYBRID_LENGTH/4;
            kmu_eap_int_to_bytes_be((uint16_t)length_pub_hybrid, output + 1);

            memset(output + 3, 0x00, 1);
            memcpy(output + 4, input, 1216);
            return KMU_EAP_AKA_ATTRIBUTE_AT_PUB_HYBRID_LENGTH;
            break;

        case KMU_EAP_AKA_ATTRIBUTE_AT_PUB_KEM:
            // MK_KEM : 1184 bytes + 2 + 1 = 1187 + 1 (padding) = 1188/4 = 299(length)
            output[0] = KMU_EAP_AKA_ATTRIBUTE_AT_PUB_KEM;
            size_t length_pub_kem = KMU_EAP_AKA_ATTRIBUTE_AT_PUB_KEM_LENGTH/4;
            kmu_eap_int_to_bytes_be((uint16_t)length_pub_kem, output + 1);

            memset(output + 3, 0x00, 1);
            memcpy(output + 4, input, 1184);
            return KMU_EAP_AKA_ATTRIBUTE_AT_PUB_KEM_LENGTH;
            break;
        
        case KMU_EAP_AKA_ATTRIBUTE_AT_KDF_FS:
            output[0] = KMU_EAP_AKA_ATTRIBUTE_AT_KDF_FS;
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


void kmu_eap_int_to_bytes_be(uint16_t value, uint8_t *out) 
{
    out[0] = (value >> 8) & 0xFF;
    out[1] = value & 0xFF;
}

void kmu_eap_pad_zeros(const uint8_t *input, size_t input_len, uint8_t *output, size_t padded_len) 
{
    memset(output, 0, padded_len);
    if (input_len > padded_len) input_len = padded_len;
    memcpy(output + (padded_len - input_len), input, input_len);
}

void kmu_eap_aka_encode_packet(kmu_eap_aka_packet_t *packet, uint8_t *output)
{
    output[0] = packet->code;
    output[1] = packet->identifier;
    output[2] = (packet->length >> 8) & 0xFF;
    output[3] = packet->length & 0xFF;
    if(packet->code==KMU_EAP_CODE_REQUEST){
        output[4] = packet->type;
        output[5] = packet->sub_type;
        output[6] = 0x00;
        output[7] = 0x00;

        size_t payload_len = packet->length - KMU_EAP_AKA_REQUEST_MIN_LENGTH;
        memcpy(output + KMU_EAP_AKA_REQUEST_MIN_LENGTH, packet->data, payload_len);

    }
}

size_t kmu_eap_aka_decode_attribute(KMUEapAkaAttributeType kmu_eap_aka_attribute_type, uint8_t *input, size_t input_len, uint8_t *output)
{   
    //start from 8
    size_t i = 8; 

    while (i + 2 <= input_len) {
        uint8_t type = input[i];
        size_t attr_total_len = 0;

        if(type==KMU_EAP_AKA_ATTRIBUTE_AT_PUB_HYBRID){
            //uint8_t len_units = input[i + 1];
            //uint16_t len_units = 281;
            attr_total_len = 1124;
        }
        else if(type==KMU_EAP_AKA_ATTRIBUTE_AT_KEM_CT){
            //uint8_t len_units = input[i + 1];
            //uint16_t len_units = 281;
            attr_total_len = 1092;
        }
        else{
            uint8_t len_units = input[i + 1];
            attr_total_len = len_units * 4;
        }
        

        //if (attr_total_len < 4 || i + attr_total_len > input_len)
        //    break;  // malformed or truncated

        if (type == kmu_eap_aka_attribute_type) {
            size_t value_len = 0;
            const uint8_t *value_ptr = NULL;

            switch (type) {
                case KMU_EAP_AKA_ATTRIBUTE_AT_RES: 
                    if (attr_total_len < 4) return 0;
                    uint16_t bit_len = (input[i + 2] << 8) | input[i + 3];
                    value_len = bit_len / 8;
                    if (value_len > attr_total_len - 4) return 0;
                    value_ptr = input + i + 4;
                    break;
                case KMU_EAP_AKA_ATTRIBUTE_AT_MAC:
                    value_len = 16;
                    value_ptr = input + i + 4;
                    break;
                case KMU_EAP_AKA_ATTRIBUTE_AT_PUB_ECDHE:
                    value_len = 32;
                    value_ptr = input + i + 4;
                    break;
                case KMU_EAP_AKA_ATTRIBUTE_AT_PUB_HYBRID:
                    value_len = 1120;
                    value_ptr = input + i + 4;
                    break;
                case KMU_EAP_AKA_ATTRIBUTE_AT_KEM_CT:
                    value_len = 1088;
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


void kmu_eap_aka_clean_mac(KMUEapAkaAttributeType kmu_eap_aka_attribute_type ,uint8_t *input, size_t input_len, uint8_t *output)
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

        if(type==KMU_EAP_AKA_ATTRIBUTE_AT_PUB_HYBRID){
            //uint8_t len_units = input[i + 1];
            //uint16_t len_units = 281;
            attr_total_len = 1124;
        }
        else if(type==KMU_EAP_AKA_ATTRIBUTE_AT_KEM_CT){
            //uint8_t len_units = input[i + 1];
            //uint16_t len_units = 281;
            attr_total_len = 1092;
        }
        else{
            uint8_t len_units = input[i + 1];
            attr_total_len = len_units * 4;
        }

        if (attr_total_len < 4 || i + attr_total_len > input_len)
            break;  // malformed or truncated

        if (type == KMU_EAP_AKA_ATTRIBUTE_AT_MAC) {
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
