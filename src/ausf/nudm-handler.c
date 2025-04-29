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
#include "eap/eap.h"

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

static bool ausf_nudm_ueau_handle_get_eap_aka_prime(ausf_ue_t *ausf_ue,
    ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{   
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

    //save RAND and XRES to AUSF_UE
    ogs_ascii_to_hex(
        AuthenticationVector->rand,
        strlen(AuthenticationVector->rand),
        ausf_ue->rand, sizeof(ausf_ue->rand));
    ogs_ascii_to_hex(
        AuthenticationVector->xres,
        strlen(AuthenticationVector->xres),
        ausf_ue->xres, sizeof(ausf_ue->xres));
    
    uint8_t ck_prime[OGS_KEY_LEN];
    uint8_t ik_prime[OGS_KEY_LEN];
    uint8_t rand[OGS_RAND_LEN];
    uint8_t xres[OGS_MAX_RES_LEN];
    uint8_t autn[OGS_AUTN_LEN];
    
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

    // copy ik prime and ck prime to ausf context 
    memcpy(ausf_ue->ik_prime,ik_prime,OGS_KEY_LEN);
    memcpy(ausf_ue->ck_prime,ck_prime,OGS_KEY_LEN);
    /*
    
    For EAP-AKA', output is 1664 bits = 208 bytes 
    For EAP-AKA'FS, there is 2 
        MK is 384 bits = 48 bytes
        MK_ECDHE is 1280 = 160 bytes 
    For EAP-AKA'-HPQC
        MK is 384 bits = 48 bytes 
        MK_HYBRID is 1280 = 160 bytes
    Key is IK' + CK'
    */ 
    uint8_t mk[208];

    eap_aka_prime_generate_mk(ausf_ue->ik_prime,ausf_ue->ck_prime, ausf_ue->supi,mk);

    memcpy(ausf_ue->k_aut,mk+16,OGS_SHA256_DIGEST_SIZE);

    // need to calculate k_ausf after EAP Response, because in FS extension, this key
    // derived from MK_ECDHE, and for HPQC it derived from MK_PQ_SHARED
    memcpy(ausf_ue->kausf,mk+144,OGS_SHA256_DIGEST_SIZE);

    // For FS and HPQC Extension 
    uint8_t pub_key_ecdhe[32]; // FS
    uint8_t encapsulation_key[1216]; // HPQC

    if(EAP_AKA_PRIME_EXTENSION==1){
        // FS Extension 
        // Generate ECDHE public key pair

        uint8_t priv_key_ecdhe[32];
        eap_aka_prime_fs_key_generation(priv_key_ecdhe,pub_key_ecdhe); 
        memcpy(ausf_ue->hnPrivateKey,priv_key_ecdhe,32);

    }
    else if(EAP_AKA_PRIME_EXTENSION==2){
        // Start X-WING Key Generation 

        uint8_t decapsulation_key[32];
        //uint8_t encapsulation_key[1216];

        // input : none 
        // output : decapsulation_key (sk)(32) and encapsulation_key (pk)(1216)
        eap_aka_prime_hpqc_xwing_key_generation(decapsulation_key, encapsulation_key);
        
        // save secret key x wing
        memcpy(ausf_ue->sk_xwing,decapsulation_key,32);
        // End of X-WING Key Generation 
    }
    
    /* Generate EAP Request Payload
     * rand, autn, kdf, kdf_input, mac
     */

    uint8_t data_attribute[OGS_MAX_EAP_PAYLOAD_LEN];

    uint8_t at_rand[EAP_AKA_ATTRIBUTE_AT_RAND_LENGTH]; // 20
    uint8_t at_autn[EAP_AKA_ATTRIBUTE_AT_AUTN_LENGTH]; // 20
    uint8_t at_kdf[EAP_AKA_ATTRIBUTE_AT_KDF_LENGTH]; // 4
    uint8_t at_mac[EAP_AKA_ATTRIBUTE_AT_MAC_LENGTH]; // 20
    size_t at_kdf_input_length = ((strlen(ausf_ue->serving_network_name) + 3)/4 + 1)*4; //36
    uint8_t at_kdf_input[at_kdf_input_length]; 

    // encode and append all attribute 
    size_t offset = 0;
    // AT_RAND
    eap_aka_encode_attribute(EAP_AKA_ATTRIBUTE_AT_RAND, rand, OGS_RAND_LEN, at_rand);
    memcpy(data_attribute + offset, at_rand, EAP_AKA_ATTRIBUTE_AT_RAND_LENGTH);
    offset+=EAP_AKA_ATTRIBUTE_AT_RAND_LENGTH;
    
    // AT_AUTN
    eap_aka_encode_attribute(EAP_AKA_ATTRIBUTE_AT_AUTN, autn, OGS_AUTN_LEN, at_autn);
    memcpy(data_attribute + offset, at_autn, EAP_AKA_ATTRIBUTE_AT_AUTN_LENGTH);
    offset+=EAP_AKA_ATTRIBUTE_AT_AUTN_LENGTH;
    
    // AT_KDF
    eap_aka_encode_attribute(EAP_AKA_ATTRIBUTE_AT_KDF, NULL, 0, at_kdf);
    memcpy(data_attribute + offset, at_kdf, EAP_AKA_ATTRIBUTE_AT_KDF_LENGTH);
    offset+=EAP_AKA_ATTRIBUTE_AT_KDF_LENGTH;

    // AT_KDF_FS
    if(EAP_AKA_PRIME_EXTENSION==1 || EAP_AKA_PRIME_EXTENSION==2){
        uint8_t at_kdf_fs[EAP_AKA_ATTRIBUTE_AT_KDF_LENGTH]; // 4
        eap_aka_encode_attribute(EAP_AKA_ATTRIBUTE_AT_KDF_FS, NULL, 0, at_kdf_fs);
        memcpy(data_attribute + offset, at_kdf_fs, EAP_AKA_ATTRIBUTE_AT_KDF_FS_LENGTH);
        offset+=EAP_AKA_ATTRIBUTE_AT_KDF_FS_LENGTH;
    }
    
    // AT_KDF_INPUT
    eap_aka_encode_attribute(EAP_AKA_ATTRIBUTE_AT_KDF_INPUT, ausf_ue->serving_network_name, strlen(ausf_ue->serving_network_name), at_kdf_input);
    memcpy(data_attribute + offset, at_kdf_input, at_kdf_input_length);
    offset+=at_kdf_input_length;

    // FS Extension
    if(EAP_AKA_PRIME_EXTENSION==1){
        uint8_t at_pub_ecdhe[EAP_AKA_ATTRIBUTE_AT_PUB_ECDHE_LENGTH];
        eap_aka_encode_attribute(EAP_AKA_ATTRIBUTE_AT_PUB_ECDHE, pub_key_ecdhe, 32, at_pub_ecdhe);
        memcpy(data_attribute + offset, at_pub_ecdhe, EAP_AKA_ATTRIBUTE_AT_PUB_ECDHE_LENGTH);
        offset+=EAP_AKA_ATTRIBUTE_AT_PUB_ECDHE_LENGTH;
    }
    // HPQC Extension
    if(EAP_AKA_PRIME_EXTENSION==2){
        uint8_t at_pub_hybrid[EAP_AKA_ATTRIBUTE_AT_PUB_HYBRID_LENGTH]; // 1220
        eap_aka_encode_attribute(EAP_AKA_ATTRIBUTE_AT_PUB_HYBRID, encapsulation_key, 1216, at_pub_hybrid);
        memcpy(data_attribute + offset, at_pub_hybrid, EAP_AKA_ATTRIBUTE_AT_PUB_HYBRID_LENGTH);
        offset+=EAP_AKA_ATTRIBUTE_AT_PUB_HYBRID_LENGTH;
    }

    // AT_MAC
    eap_aka_encode_attribute(EAP_AKA_ATTRIBUTE_AT_MAC, NULL, OGS_RAND_LEN, at_mac);
    memcpy(data_attribute + offset, at_mac, EAP_AKA_ATTRIBUTE_AT_MAC_LENGTH);
    offset+=EAP_AKA_ATTRIBUTE_AT_MAC_LENGTH;
    
    // create eap_request 
    size_t eap_request_length = sizeof(eap_aka_packet_t) + offset;
    eap_aka_packet_t *eap_request_packet = malloc(eap_request_length);

    uint8_t eap_request[eap_request_length];
    
    eap_aka_build_request(eap_request_packet, EAP_AKA_SUBTYPE_AKA_CHALLENGE, offset, data_attribute);
    eap_aka_encode_packet(eap_request_packet, eap_request);

    //mac calculation 
    ogs_hmac_sha256(ausf_ue->k_aut, OGS_SHA256_DIGEST_SIZE, eap_request, eap_request_length, at_mac+4, OGS_SHA256_DIGEST_SIZE);

    //copy back at_mac
    memcpy(eap_request + (eap_request_length - EAP_AKA_ATTRIBUTE_AT_MAC_LENGTH), at_mac, EAP_AKA_ATTRIBUTE_AT_MAC_LENGTH);

    char eap_request_base64[((eap_request_length + 2) / 3) * 4 + 1];
    ogs_base64_encode_binary(eap_request_base64, eap_request, eap_request_length);

    // End of EAP Payload Generation

    memset(&UeAuthenticationCtx, 0, sizeof(UeAuthenticationCtx));

    UeAuthenticationCtx.auth_type = ausf_ue->auth_type;

    memset(&AuthData, 0, sizeof(AuthData));
    
    AuthData.is_eap_payload = true;
    AuthData.eap_payload.eap_payload = eap_request_base64;

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

        // check which extension is used 
        // Normal EAP-AKA' 
        // EAP-AKA'-FS
        // EAP-AKA'-HPQC
        uint8_t shared_key[32];

        if(EAP_AKA_PRIME_EXTENSION == 1){
            // FS Extension 
            // Input : HN Private Key, UE Public Key
            // Output : Shared Key
            eap_aka_prime_fs_generate_shared_key(shared_key,ausf_ue->hnPrivateKey,ausf_ue->uePublicKey); 

        }
        else if(EAP_AKA_PRIME_EXTENSION == 2){
            // HPQC Extension 

            // Input : X-Wing Ciphertext from UE, X-Wing shared key from HN
            //          ausf_ue->ct_xwing, ausf_ue->sk_xwing
            // Output : Shared Key
            eap_aka_prime_hpqc_xwing_decapsulate(shared_key,ausf_ue->ct_xwing,ausf_ue->sk_xwing);
        }

        if(EAP_AKA_PRIME_EXTENSION == 1 || EAP_AKA_PRIME_EXTENSION == 2){
            // generate MK_ECDHE(FS) or MK_SHARED (HPQC)
            // input: ik_prime, ck_prime, shared_key, prefix ("EAP-AKA' FS"), supi
            // output: mk_ecdhe / mk_shared (64 bytes)
            uint8_t mk_shared[160];
            eap_aka_prime_generate_mk_shared(ausf_ue->ik_prime,ausf_ue->ck_prime,shared_key, ausf_ue->supi, mk_shared);

            // update K_AUSF
            memcpy(ausf_ue->kausf,mk_shared+96,32);
        }

        ogs_kdf_kseaf(ausf_ue->serving_network_name,
            ausf_ue->kausf, ausf_ue->kseaf);
        ogs_hex_to_ascii(ausf_ue->kseaf, sizeof(ausf_ue->kseaf),
                kseaf_string, sizeof(kseaf_string));
        EapSession.k_seaf = kseaf_string;

        
        // create eap_sucess_packet
        size_t eap_success_packet_length = 4;
        uint8_t eap_success[eap_success_packet_length];
        char *eap_response_base64 = malloc(((eap_success_packet_length + 2) / 3) * 4 + 1);
        eap_aka_packet_t *eap_response_packet = malloc(eap_success_packet_length);

        eap_aka_build_success(eap_response_packet);
        eap_aka_encode_packet(eap_response_packet,eap_success);
        ogs_base64_encode_binary(eap_response_base64, eap_success, eap_success_packet_length);

        EapSession.eap_payload = eap_response_base64;

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