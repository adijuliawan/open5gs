/*
 * Copyright (C) 2019 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "nudm-handler.h"

static const char *links_member_name(OpenAPI_auth_type_e auth_type)
{
    if (auth_type == OpenAPI_auth_type_5G_AKA ) {
        return OGS_SBI_RESOURCE_NAME_5G_AKA;
    } else if (auth_type == OpenAPI_auth_type_EAP_AKA_PRIME) {
        return OGS_SBI_RESOURCE_NAME_EAP_SESSION;
    } 
    else if (auth_type == OpenAPI_auth_type_EAP_TLS) {
        return OGS_SBI_RESOURCE_NAME_EAP_SESSION;
    }

    ogs_assert_if_reached();
    return NULL;
}

static bool ausf_nudm_ueau_handle_get_5g_aka(ausf_ue_t *ausf_ue,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    ogs_sbi_server_t *server = NULL;

    ogs_sbi_message_t sendmsg;
    ogs_sbi_header_t header;
    ogs_sbi_response_t *response = NULL;

    char hxres_star_string[OGS_KEYSTRLEN(OGS_MAX_RES_LEN)];

    OpenAPI_authentication_info_result_t *AuthenticationInfoResult = NULL;
    OpenAPI_authentication_vector_t *AuthenticationVector = NULL;
    OpenAPI_ue_authentication_ctx_t UeAuthenticationCtx;
    OpenAPI_ue_authentication_ctx_5g_auth_data_t AuthData;
    OpenAPI_map_t *LinksValueScheme = NULL;
    OpenAPI_links_value_schema_t LinksValueSchemeValue;

    ogs_assert(ausf_ue);
    ogs_assert(stream);
    ogs_assert(recvmsg);
    server = ogs_sbi_server_from_stream(stream);
    ogs_assert(server);

    AuthenticationInfoResult = recvmsg->AuthenticationInfoResult;
    AuthenticationVector =
        AuthenticationInfoResult->authentication_vector;

    if (!AuthenticationVector->rand) {
        ogs_error("[%s] No AuthenticationVector.rand", ausf_ue->suci);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No AuthenticationVector.rand", ausf_ue->suci,
                NULL));
        return false;
    }

    if (!AuthenticationVector->xres_star) {
        ogs_error("[%s] No AuthenticationVector.xresStar",
                ausf_ue->suci);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No AuthenticationVector.xresStar", ausf_ue->suci,
                NULL));
        return false;
    }

    if (!AuthenticationVector->autn) {
        ogs_error("[%s] No AuthenticationVector.autn", ausf_ue->suci);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No AuthenticationVector.autn", ausf_ue->suci,
                NULL));
        return false;
    }

    if (!AuthenticationVector->kausf) {
        ogs_error("[%s] No AuthenticationVector.kausf", ausf_ue->suci);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No AuthenticationVector.kausf", ausf_ue->suci,
                NULL));
        return false;
    }

    if (!AuthenticationInfoResult->supi) {
        ogs_error("[%s] No AuthenticationVector.supi", ausf_ue->suci);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No AuthenticationVector.supi", ausf_ue->suci,
                NULL));
        return false;
    }

    /* SUPI */
    if (ausf_ue->supi) {
        ogs_hash_set(ausf_self()->supi_hash,
                ausf_ue->supi, strlen(ausf_ue->supi), NULL);
        ogs_free(ausf_ue->supi);
    }
    ausf_ue->supi = ogs_strdup(AuthenticationInfoResult->supi);
    ogs_assert(ausf_ue->supi);
    ogs_hash_set(ausf_self()->supi_hash,
            ausf_ue->supi, strlen(ausf_ue->supi), ausf_ue);

    ausf_ue->auth_type = AuthenticationInfoResult->auth_type;

    ogs_ascii_to_hex(
        AuthenticationVector->rand,
        strlen(AuthenticationVector->rand),
        ausf_ue->rand, sizeof(ausf_ue->rand));
    ogs_ascii_to_hex(
        AuthenticationVector->xres_star,
        strlen(AuthenticationVector->xres_star),
        ausf_ue->xres_star, sizeof(ausf_ue->xres_star));
    ogs_ascii_to_hex(
        AuthenticationVector->kausf,
        strlen(AuthenticationVector->kausf),
        ausf_ue->kausf, sizeof(ausf_ue->kausf));

    memset(&UeAuthenticationCtx, 0, sizeof(UeAuthenticationCtx));

    UeAuthenticationCtx.auth_type = ausf_ue->auth_type;

    memset(&AuthData, 0, sizeof(AuthData));
    AuthData.av_5g_aka.rand = AuthenticationVector->rand;
    AuthData.av_5g_aka.autn = AuthenticationVector->autn;

    ogs_kdf_hxres_star(ausf_ue->rand, ausf_ue->xres_star,
            ausf_ue->hxres_star);
    ogs_hex_to_ascii(ausf_ue->hxres_star, sizeof(ausf_ue->hxres_star),
            hxres_star_string, sizeof(hxres_star_string));
    AuthData.av_5g_aka.hxres_star = hxres_star_string;

    UeAuthenticationCtx._5g_auth_data = &AuthData;

    memset(&LinksValueSchemeValue, 0, sizeof(LinksValueSchemeValue));

    memset(&header, 0, sizeof(header));
    header.service.name = (char *)OGS_SBI_SERVICE_NAME_NAUSF_AUTH;
    header.api.version = (char *)OGS_SBI_API_V1;
    header.resource.component[0] =
            (char *)OGS_SBI_RESOURCE_NAME_UE_AUTHENTICATIONS;
    header.resource.component[1] = ausf_ue->ctx_id;
    header.resource.component[2] =
            (char *)OGS_SBI_RESOURCE_NAME_5G_AKA_CONFIRMATION;
    LinksValueSchemeValue.href = ogs_sbi_server_uri(server, &header);
    LinksValueScheme = OpenAPI_map_create(
            (char *)links_member_name(UeAuthenticationCtx.auth_type),
            &LinksValueSchemeValue);
    ogs_assert(LinksValueScheme);

    UeAuthenticationCtx._links = OpenAPI_list_create();
    ogs_assert(UeAuthenticationCtx._links);
    OpenAPI_list_add(UeAuthenticationCtx._links, LinksValueScheme);

    memset(&sendmsg, 0, sizeof(sendmsg));

    memset(&header, 0, sizeof(header));
    header.service.name = (char *)OGS_SBI_SERVICE_NAME_NAUSF_AUTH;
    header.api.version = (char *)OGS_SBI_API_V1;
    header.resource.component[0] =
            (char *)OGS_SBI_RESOURCE_NAME_UE_AUTHENTICATIONS;
    header.resource.component[1] = ausf_ue->ctx_id;

    sendmsg.http.location = ogs_sbi_server_uri(server, &header);
    sendmsg.http.content_type = (char *)OGS_SBI_CONTENT_3GPPHAL_TYPE;

    sendmsg.UeAuthenticationCtx = &UeAuthenticationCtx;

    response = ogs_sbi_build_response(&sendmsg, OGS_SBI_HTTP_STATUS_CREATED);
    ogs_assert(response);
    ogs_assert(true == ogs_sbi_server_send_response(stream, response));

    OpenAPI_list_free(UeAuthenticationCtx._links);
    OpenAPI_map_free(LinksValueScheme);

    ogs_free(LinksValueSchemeValue.href);
    ogs_free(sendmsg.http.location);

    return true;
}

void write_be16(uint8_t *dst, uint16_t val) {
    dst[0] = (val >> 8) & 0xFF;
    dst[1] = val & 0xFF;
}

int encode_at_rand(uint8_t *buf, const uint8_t *rand) {
    buf[0] = 1; //AT_RAND_ATTRIBUTE              1
    buf[1] = 5;
    buf[2] = buf[3] = 0x00;
    memcpy(buf + 4, rand, 16);
    return 20;
}

int encode_at_autn(uint8_t *buf, const uint8_t *autn) {
    buf[0] = 2; //AT_AUTN_ATTRIBUTE              2
    buf[1] = 5;
    buf[2] = buf[3] = 0x00;
    memcpy(buf + 4, autn, 16);
    return 20;
}

int encode_at_kdf(uint8_t *buf) {
    buf[0] = 24; // AT_KDF_ATTRIBUTE               24
    buf[1] = 1;
    buf[2] = 0x00;
    buf[3] = 0x01;
    return 4;
}

void int_to_bytes_be(uint16_t value, uint8_t *out) {
    out[0] = (value >> 8) & 0xFF;
    out[1] = value & 0xFF;
}

void pad_zeros(const uint8_t *input, size_t input_len, uint8_t *output, size_t padded_len) {
    memset(output, 0, padded_len);
    if (input_len > padded_len) input_len = padded_len;
    memcpy(output + (padded_len - input_len), input, input_len);
}


int encode_at_kdf_input(uint8_t *buf, const uint8_t *data, size_t len) {
    int length = (len + 3) / 4 + 1;
    buf[0] = 23; // AT_KDF_INPUT_ATTRIBUTE      23
    buf[1] = (uint8_t)length;
    int_to_bytes_be((uint16_t)len, buf + 2);
    pad_zeros(data, len, buf + 4, (length - 1) * 4);
    return length * 4; //36
}

int encode_at_res(uint8_t *buf, const uint8_t *data, size_t len) {
    int length = (len + 3) / 4 + 1;
    buf[0] = 3; // AT_RES_ATTRIBUTE               3
    buf[1] = (uint8_t)length;
    buf[2] = (len >> 8) & 0xFF;
    buf[3] = len & 0xFF;
    memset(buf + 4, 0, (length - 1) * 4);
    memcpy(buf + 4, data, len);
    return length * 4;
}

int encode_at_mac(uint8_t *buf) {
    buf[0] = 11; // AT_MAC_ATTRIBUTE               11
    buf[1] = 5;
    buf[2] = buf[3] = 0x00;
    memset(buf + 4, 0x00, 16);
    return 20;
}

void calculate_at_mac(const uint8_t *key, const uint8_t *data, size_t len, uint8_t *mac_out) {
    ogs_hmac_sha256(key, 32, data, len, mac_out, OGS_SHA256_DIGEST_SIZE);
}

char *base64_encode(const uint8_t *data, size_t len) {
    BIO *bio, *b64;
    BUF_MEM *buffer_ptr;
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);
    BIO_write(bio, data, len);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &buffer_ptr);
    char *b64text = malloc(buffer_ptr->length + 1);
    memcpy(b64text, buffer_ptr->data, buffer_ptr->length);
    b64text[buffer_ptr->length] = '\0';
    BIO_free_all(bio);
    return b64text;
}

static bool ausf_nudm_ueau_handle_get_eap_aka_prime(ausf_ue_t *ausf_ue,
    ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{   
    ogs_debug("[EAP_AKA_PRIME] Start EAP-AKA-PRIME at AUSF");
    //ogs_error("[%s] EAP-AKA' not implemented yet", ausf_ue->suci);
    //ogs_assert(true ==
    //    ogs_sbi_server_send_error(stream,
    //        OGS_SBI_HTTP_STATUS_NOT_IMPLEMENTED,
    //        recvmsg, "EAP-AKA' not implemented yet", ausf_ue->suci, NULL));
    //return false;

    ogs_sbi_server_t *server = NULL;

    ogs_sbi_message_t sendmsg;
    ogs_sbi_header_t header;
    ogs_sbi_response_t *response = NULL;


    OpenAPI_authentication_info_result_t *AuthenticationInfoResult = NULL;
    OpenAPI_authentication_vector_t *AuthenticationVector = NULL;
    OpenAPI_ue_authentication_ctx_t UeAuthenticationCtx;
    OpenAPI_ue_authentication_ctx_5g_auth_data_t AuthData;
    OpenAPI_map_t *LinksValueScheme = NULL;
    OpenAPI_links_value_schema_t LinksValueSchemeValue;

    ogs_assert(ausf_ue);
    ogs_assert(stream);
    ogs_assert(recvmsg);
    server = ogs_sbi_server_from_stream(stream);
    ogs_assert(server);


    ogs_debug("[EAP_AKA_PRIME] Start EAP-AKA-PRIME ");
    AuthenticationInfoResult = recvmsg->AuthenticationInfoResult;
    AuthenticationVector =
        AuthenticationInfoResult->authentication_vector;

    if (!AuthenticationVector->rand) {
        ogs_error("[%s] No AuthenticationVector.rand", ausf_ue->suci);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No AuthenticationVector.rand", ausf_ue->suci,
                NULL));
        return false;
    }

    if (!AuthenticationVector->xres) {
        ogs_error("[%s] No AuthenticationVector.xres",
                ausf_ue->suci);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No AuthenticationVector.xres", ausf_ue->suci,
                NULL));
        return false;
    }

    if (!AuthenticationVector->autn) {
        ogs_error("[%s] No AuthenticationVector.autn", ausf_ue->suci);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No AuthenticationVector.autn", ausf_ue->suci,
                NULL));
        return false;
    }

    if (!AuthenticationVector->ck_prime) {
        ogs_error("[%s] No AuthenticationVector.ckPrime", ausf_ue->suci);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No AuthenticationVector.ckPrime", ausf_ue->suci,
                NULL));
        return false;
    }

    if (!AuthenticationVector->ik_prime) {
        ogs_error("[%s] No AuthenticationVector.ikPrime", ausf_ue->suci);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No AuthenticationVector.ikPrime", ausf_ue->suci,
                NULL));
        return false;
    }

    if (!AuthenticationInfoResult->supi) {
        ogs_error("[%s] No AuthenticationVector.supi", ausf_ue->suci);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No AuthenticationVector.supi", ausf_ue->suci,
                NULL));
        return false;
    }

    /* SUPI */
    if (ausf_ue->supi) {
        ogs_hash_set(ausf_self()->supi_hash,
                ausf_ue->supi, strlen(ausf_ue->supi), NULL);
        ogs_free(ausf_ue->supi);
    }
    ausf_ue->supi = ogs_strdup(AuthenticationInfoResult->supi);
    ogs_assert(ausf_ue->supi);
    ogs_hash_set(ausf_self()->supi_hash,
            ausf_ue->supi, strlen(ausf_ue->supi), ausf_ue);

    ausf_ue->auth_type = AuthenticationInfoResult->auth_type;

    //save variable to AUSF_UE (RAND? & XRES?)
    ogs_ascii_to_hex(
        AuthenticationVector->rand,
        strlen(AuthenticationVector->rand),
        ausf_ue->rand, sizeof(ausf_ue->rand));
    ogs_ascii_to_hex(
        AuthenticationVector->xres,
        strlen(AuthenticationVector->xres),
        ausf_ue->xres, sizeof(ausf_ue->xres));
    
    //derive K_AUT, K_AUSF from PRF(ikPrime,ckPrime,identity)
    // / uint8_t *ck_prime, uint8_t *ik_prime, const char *supi,
    //uint8_t *k_encr, uint8_t *k_aut, uint8_t *k_re, uint8_t *msk, uint8_t *emsk 

    //get RAND, XRES, AUTN 
   

    // char rand_string[OGS_KEYSTRLEN(OGS_RAND_LEN)];
    // char xres_string[OGS_KEYSTRLEN(OGS_MAX_RES_LEN)];
    // char autn_string[OGS_KEYSTRLEN(OGS_AUTN_LEN)];

    // ogs_ascii_to_hex(
    //     AuthenticationVector->rand,
    //     strlen(AuthenticationVector->rand),
    //     rand_string, sizeof(rand_string));

    // ogs_ascii_to_hex(
    //     AuthenticationVector->xres,
    //     strlen(AuthenticationVector->xres),
    //     xres_string, sizeof(xres_string));

    // ogs_ascii_to_hex(
    //     AuthenticationVector->autn,
    //     strlen(AuthenticationVector->autn),
    //     autn_string, sizeof(autn_string));
    
    
    uint8_t ck_prime[OGS_KEY_LEN];
    uint8_t ik_prime[OGS_KEY_LEN];
    uint8_t rand[OGS_RAND_LEN];
    uint8_t xres[OGS_MAX_RES_LEN];
    uint8_t autn[OGS_AUTN_LEN];

    
    


    uint8_t k_encr[OGS_KEY_LEN];
    uint8_t k_aut[OGS_KEY_LEN*2];
    uint8_t k_re[OGS_KEY_LEN*2];
    uint8_t msk[OGS_KEY_LEN*4];
    uint8_t emsk[OGS_KEY_LEN*4];

    
    ogs_debug("[EAP_AKA_PRIME] CK_PRIME [%s]",AuthenticationVector->ck_prime);
    ogs_debug("[EAP_AKA_PRIME] IK_PRIME [%s]",AuthenticationVector->ik_prime);
    ogs_debug("[EAP_AKA_PRIME] RAND [%s]", AuthenticationVector->rand);
    ogs_debug("[EAP_AKA_PRIME] XRES [%s]", AuthenticationVector->xres);
    ogs_debug("[EAP_AKA_PRIME] AUTN [%s]", AuthenticationVector->autn);
    
    ogs_ascii_to_hex(
        AuthenticationVector->ck_prime,
        strlen(AuthenticationVector->ck_prime),
        ck_prime, sizeof(ck_prime));
    ogs_ascii_to_hex(
        AuthenticationVector->ik_prime,
        strlen(AuthenticationVector->ik_prime),
        ik_prime, sizeof(ik_prime));

    ogs_ascii_to_hex(
        AuthenticationVector->rand,
        strlen(AuthenticationVector->rand),
        rand, sizeof(rand));

    ogs_ascii_to_hex(
        AuthenticationVector->xres,
        strlen(AuthenticationVector->xres),
        xres, sizeof(xres));

    ogs_ascii_to_hex(
        AuthenticationVector->autn,
        strlen(AuthenticationVector->autn),
        autn, sizeof(autn));

    ogs_kdf_prf_prime(ik_prime, ck_prime,ausf_ue->supi,
        k_encr,k_aut,k_re,msk,emsk);    
    
    //ogs_hex_to_ascii(udm_ue->rand, sizeof(udm_ue->rand),
    //    rand_string, sizeof(rand_string));
    
    char k_encr_string[OGS_KEYSTRLEN(OGS_KEY_LEN)];
    char k_aut_string[OGS_KEYSTRLEN(OGS_KEY_LEN*2)];
    char k_re_string[OGS_KEYSTRLEN(OGS_KEY_LEN*2)];
    char msk_string[OGS_KEYSTRLEN(OGS_KEY_LEN*4)];
    char emsk_string[OGS_KEYSTRLEN(OGS_KEY_LEN*4)];

    ogs_hex_to_ascii(k_encr, sizeof(k_encr),
        k_encr_string, sizeof(k_encr_string));
    ogs_hex_to_ascii(k_aut, sizeof(k_aut),
        k_aut_string, sizeof(k_aut_string));
    ogs_hex_to_ascii(k_re, sizeof(k_re),
        k_re_string, sizeof(k_re_string));
    ogs_hex_to_ascii(msk, sizeof(msk),
        msk_string, sizeof(msk_string));
    ogs_hex_to_ascii(emsk, sizeof(emsk),
        emsk_string, sizeof(emsk_string));
    
    ogs_debug("[EAP_AKA_PRIME] K_encr : [%s]", k_encr_string);
    ogs_debug("[EAP_AKA_PRIME] K_aut : [%s]", k_aut_string);
    ogs_debug("[EAP_AKA_PRIME] K_re : [%s]", k_re_string);
    ogs_debug("[EAP_AKA_PRIME] MSK : [%s]", msk_string);
    ogs_debug("[EAP_AKA_PRIME] EMSK : [%s]", emsk_string);

    //copy kausf from msk 
    memcpy(ausf_ue->kausf,emsk,OGS_SHA256_DIGEST_SIZE);

    char kausf_string[OGS_KEYSTRLEN(OGS_SHA256_DIGEST_SIZE)];
    ogs_hex_to_ascii(ausf_ue->kausf, sizeof(ausf_ue->kausf),
        kausf_string, sizeof(kausf_string));
    ogs_debug("[EAP_AKA_PRIME] K_AUSF : [%s]", kausf_string);

    ogs_debug("[EAP_AKA_PRIME] Serving Network : [%s]", ausf_ue->serving_network_name);
    // generate eap packet / eap_payload 
    uint8_t eap_header[5] = {
        1,
        32,
        0x00, 0x00,
        50
    };

    uint8_t payload[512];
    size_t offset = 0;

    payload[offset++] = 1; // AKA_CHALLENGE_SUBTYPE               1
    payload[offset++] = 0x00;
    payload[offset++] = 0x00;

    offset += encode_at_rand(payload + offset, rand);
    offset += encode_at_autn(payload + offset, autn);
    offset += encode_at_kdf(payload + offset);
    offset += encode_at_kdf_input(payload + offset, (const uint8_t *)ausf_ue->serving_network_name, strlen(ausf_ue->serving_network_name));
    //offset += encode_at_res(payload + offset, res, res_len);
    size_t mac_pos = offset;
    offset += encode_at_mac(payload + offset);

    uint16_t total_len = offset + 5;
    write_be16(&eap_header[2], total_len);

    uint8_t *encoded = malloc(total_len);
    memcpy(encoded, eap_header, 5);
    memcpy(encoded + 5, payload, offset);

    uint8_t mac[OGS_SHA256_DIGEST_SIZE];

    char at_mac_string[OGS_KEYSTRLEN(OGS_SHA256_DIGEST_SIZE)];
    

    calculate_at_mac(k_aut, encoded, total_len, mac);
    memcpy(encoded + 5 + mac_pos + 4, mac, 16);

    ogs_hex_to_ascii(mac, sizeof(mac),
        at_mac_string, sizeof(at_mac_string));

    ogs_debug("[EAP_AKA_PRIME] AT_MAC : [%s]", at_mac_string);

    char *b64eap = base64_encode(encoded, total_len);

    ogs_debug("[EAP_AKA_PRIME] EAP Payload : [%s]", b64eap);
    //

    memset(&UeAuthenticationCtx, 0, sizeof(UeAuthenticationCtx));

    UeAuthenticationCtx.auth_type = ausf_ue->auth_type;

    memset(&AuthData, 0, sizeof(AuthData));
    
    //AuthData.eap_payload = ausf_ue->xres;
    AuthData.is_eap_payload = true;
    AuthData.eap_payload.eap_payload = b64eap;


    //AuthData.av_5g_aka.rand = AuthenticationVector->rand;
    //AuthData.av_5g_aka.autn = AuthenticationVector->autn;

    // ogs_kdf_hxres_star(ausf_ue->rand, ausf_ue->xres_star,
    //         ausf_ue->hxres_star);
    // ogs_hex_to_ascii(ausf_ue->hxres_star, sizeof(ausf_ue->hxres_star),
    //         hxres_star_string, sizeof(hxres_star_string));
    // AuthData.av_5g_aka.hxres_star = hxres_star_string;

    UeAuthenticationCtx._5g_auth_data = &AuthData;

    memset(&LinksValueSchemeValue, 0, sizeof(LinksValueSchemeValue));

    memset(&header, 0, sizeof(header));
    header.service.name = (char *)OGS_SBI_SERVICE_NAME_NAUSF_AUTH;
    header.api.version = (char *)OGS_SBI_API_V1;
    header.resource.component[0] =
            (char *)OGS_SBI_RESOURCE_NAME_UE_AUTHENTICATIONS;
    header.resource.component[1] = ausf_ue->ctx_id;
    header.resource.component[2] =
            (char *)OGS_SBI_RESOURCE_NAME_EAP_SESSION;
    LinksValueSchemeValue.href = ogs_sbi_server_uri(server, &header);
    LinksValueScheme = OpenAPI_map_create(
            (char *)links_member_name(UeAuthenticationCtx.auth_type),
            &LinksValueSchemeValue);
    ogs_assert(LinksValueScheme);

    UeAuthenticationCtx._links = OpenAPI_list_create();
    ogs_assert(UeAuthenticationCtx._links);
    OpenAPI_list_add(UeAuthenticationCtx._links, LinksValueScheme);

    memset(&sendmsg, 0, sizeof(sendmsg));

    memset(&header, 0, sizeof(header));
    header.service.name = (char *)OGS_SBI_SERVICE_NAME_NAUSF_AUTH;
    header.api.version = (char *)OGS_SBI_API_V1;
    header.resource.component[0] =
            (char *)OGS_SBI_RESOURCE_NAME_UE_AUTHENTICATIONS;
    header.resource.component[1] = ausf_ue->ctx_id;

    sendmsg.http.location = ogs_sbi_server_uri(server, &header);
    sendmsg.http.content_type = (char *)OGS_SBI_CONTENT_3GPPHAL_TYPE;

    sendmsg.UeAuthenticationCtx = &UeAuthenticationCtx;

    response = ogs_sbi_build_response(&sendmsg, OGS_SBI_HTTP_STATUS_CREATED);
    ogs_assert(response);
    ogs_assert(true == ogs_sbi_server_send_response(stream, response));

    OpenAPI_list_free(UeAuthenticationCtx._links);
    OpenAPI_map_free(LinksValueScheme);

    ogs_free(LinksValueSchemeValue.href);
    ogs_free(sendmsg.http.location);

    

    return true;

}


bool ausf_nudm_ueau_handle_get(ausf_ue_t *ausf_ue,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    OpenAPI_authentication_info_result_t *AuthenticationInfoResult = NULL;
    OpenAPI_authentication_vector_t *AuthenticationVector = NULL;

    ogs_assert(ausf_ue);
    ogs_assert(stream);
    ogs_assert(recvmsg);

    AuthenticationInfoResult = recvmsg->AuthenticationInfoResult;
    if (!AuthenticationInfoResult) {
        ogs_error("[%s] No AuthenticationInfoResult", ausf_ue->suci);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No AuthenticationInfoResult", ausf_ue->suci, NULL));
        return false;
    }

    /* See TS29.509 6.1.7.3 Application Errors */
    if (AuthenticationInfoResult->auth_type != OpenAPI_auth_type_5G_AKA &&
            AuthenticationInfoResult->auth_type != OpenAPI_auth_type_EAP_AKA_PRIME) {
        ogs_error("[%s] Not supported Auth Method [%d]",
            ausf_ue->suci, AuthenticationInfoResult->auth_type);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_NOT_IMPLEMENTED,
                recvmsg, "Not supported Auth Method", ausf_ue->suci,
                "AUTHENTICATION_REJECTED"));
        return false;
    }

    AuthenticationVector =
        AuthenticationInfoResult->authentication_vector;
    if (!AuthenticationVector) {
        ogs_error("[%s] No AuthenticationVector", ausf_ue->suci);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No AuthenticationVector", ausf_ue->suci, NULL));
        return false;
    }

    if (AuthenticationVector->av_type == OpenAPI_av_type_5G_HE_AKA) {
        return ausf_nudm_ueau_handle_get_5g_aka(ausf_ue, stream, recvmsg);
    } else if (AuthenticationVector->av_type == OpenAPI_av_type_EAP_AKA_PRIME) {
        return ausf_nudm_ueau_handle_get_eap_aka_prime(ausf_ue, stream, recvmsg);
    } else {
        /*
         * TS29.509
         * 5.2.2.2.2 5G AKA 
         *
         * On failure or redirection, one of the HTTP status code
         * listed in table 6.1.7.3-1 shall be returned with the message
         * body containing a ProblemDetails structure with the "cause"
         * attribute set to one of the application error listed in
         * Table 6.1.7.3-1.
         * Application Error: AUTHENTICATION_REJECTED
         * HTTP status code: 403 Forbidden
         * Description: The user cannot be authenticated with this
         * authentication method e.g. only SIM data available 
         */
        ogs_error("[%s] Not supported Auth Method [%d]",
            ausf_ue->suci, AuthenticationVector->av_type);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_FORBIDDEN,
                recvmsg, "Not supported Auth Method", ausf_ue->suci, NULL));
        return false;
    }
}

bool ausf_nudm_ueau_handle_auth_removal_ind(ausf_ue_t *ausf_ue,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    ogs_sbi_message_t sendmsg;
    ogs_sbi_response_t *response = NULL;

    ogs_assert(ausf_ue);
    ogs_assert(stream);

    memset(&sendmsg, 0, sizeof(sendmsg));
    response = ogs_sbi_build_response(&sendmsg, OGS_SBI_HTTP_STATUS_NO_CONTENT);
    ogs_assert(response);
    ogs_assert(true == ogs_sbi_server_send_response(stream, response));

    return true;
}

bool ausf_nudm_ueau_handle_result_confirmation_inform(ausf_ue_t *ausf_ue,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    ogs_sbi_message_t sendmsg;
    ogs_sbi_response_t *response = NULL;

    char kseaf_string[OGS_KEYSTRLEN(OGS_SHA256_DIGEST_SIZE)];

    OpenAPI_confirmation_data_response_t ConfirmationDataResponse;

    OpenAPI_eap_session_t EapSession;

    OpenAPI_auth_event_t *AuthEvent = NULL;

    bool rc;
    ogs_sbi_client_t *client = NULL;
    OpenAPI_uri_scheme_e scheme = OpenAPI_uri_scheme_NULL;
    char *fqdn = NULL;
    uint16_t fqdn_port = 0;
    ogs_sockaddr_t *addr = NULL, *addr6 = NULL;

    ogs_assert(ausf_ue);
    ogs_assert(stream);

    ogs_assert(recvmsg);

    AuthEvent = recvmsg->AuthEvent;
    if (!AuthEvent) {
        ogs_error("[%s] No AuthEvent", ausf_ue->suci);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, "No AuthEvent", ausf_ue->suci, NULL));
        return false;
    }

    if (!recvmsg->http.location) {
        ogs_error("[%s] No Location", ausf_ue->suci);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, "No Location", ausf_ue->suci, NULL));
        return false;
    }

    rc = ogs_sbi_getaddr_from_uri(
            &scheme, &fqdn, &fqdn_port, &addr, &addr6, recvmsg->http.location);
    if (rc == false || scheme == OpenAPI_uri_scheme_NULL) {
        ogs_error("[%s] Invalid URI [%s]",
                ausf_ue->suci, recvmsg->http.location);

        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, "Invalid URI", ausf_ue->suci, NULL));

        return false;
    }

    client = ogs_sbi_client_find(scheme, fqdn, fqdn_port, addr, addr6);
    if (!client) {
        ogs_debug("[%s] ogs_sbi_client_add()", ausf_ue->suci);
        client = ogs_sbi_client_add(scheme, fqdn, fqdn_port, addr, addr6);
        ogs_assert(client);
    }

    OGS_SBI_SETUP_CLIENT(&ausf_ue->auth_event, client);

    ogs_free(fqdn);
    ogs_freeaddrinfo(addr);
    ogs_freeaddrinfo(addr6);

    AUTH_EVENT_STORE(ausf_ue, recvmsg->http.location);

    if (AuthEvent->success == true)
        ausf_ue->auth_result = OpenAPI_auth_result_AUTHENTICATION_SUCCESS;
    else
        ausf_ue->auth_result = OpenAPI_auth_result_AUTHENTICATION_FAILURE;


    ogs_debug("[EAP_AKA_PRIME] AuthType [%d]",AuthEvent->auth_type);

    if(AuthEvent->auth_type==OpenAPI_auth_type_EAP_AKA_PRIME){
        memset(&EapSession, 0, sizeof(EapSession));
        EapSession.auth_result = ausf_ue->auth_result;
        EapSession.supi = ausf_ue->supi; 

        ogs_kdf_kseaf(ausf_ue->serving_network_name,
            ausf_ue->kausf, ausf_ue->kseaf);
        ogs_hex_to_ascii(ausf_ue->kseaf, sizeof(ausf_ue->kseaf),
                kseaf_string, sizeof(kseaf_string));
        EapSession.k_seaf = kseaf_string;

        //make eap success packet 

        uint8_t eap_success[4];
    
        uint8_t identifier = 0x05; // Example identifier

        eap_success[0] = 0x03;             // Code: EAP-Success
        eap_success[1] = identifier;       // Identifier
        eap_success[2] = 0x00;             // Length high byte
        eap_success[3] = 0x04;
        
        char *b64eap_success = base64_encode(eap_success, sizeof(eap_success));
        ogs_debug("[EAP_AKA_PRIME] EAP Payload [%s]",b64eap_success);
        EapSession.eap_payload = b64eap_success;



        memset(&sendmsg, 0, sizeof(sendmsg));
    
        sendmsg.EapSession = &EapSession;


    } else{
        memset(&ConfirmationDataResponse, 0, sizeof(ConfirmationDataResponse));

        ConfirmationDataResponse.auth_result = ausf_ue->auth_result;
        ConfirmationDataResponse.supi = ausf_ue->supi;
    
        ogs_kdf_kseaf(ausf_ue->serving_network_name,
                ausf_ue->kausf, ausf_ue->kseaf);
        ogs_hex_to_ascii(ausf_ue->kseaf, sizeof(ausf_ue->kseaf),
                kseaf_string, sizeof(kseaf_string));
        ConfirmationDataResponse.kseaf = kseaf_string;
    
        memset(&sendmsg, 0, sizeof(sendmsg));
    
        sendmsg.ConfirmationDataResponse = &ConfirmationDataResponse;
    }
    
   

    response = ogs_sbi_build_response(&sendmsg, OGS_SBI_HTTP_STATUS_OK);
    ogs_assert(response);
    ogs_assert(true == ogs_sbi_server_send_response(stream, response));

    return true;
}