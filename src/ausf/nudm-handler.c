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
#include "oqs/oqs.h"
#include "oqs/sha3.h"

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

    // copy ik prime and ck prime to ausf context 
    memcpy(ausf_ue->ik_prime,ik_prime,OGS_KEY_LEN);
    memcpy(ausf_ue->ck_prime,ck_prime,OGS_KEY_LEN);
    /*
    new engine for PRF PRIME 
    
    For EAP-AKA', output is 1664 bits = 208 bytes 
    For EAP-AKA'FS, there is 2 
        MK is 384 bits = 48 bytes
        MK_ECDHE is 1280 = 160 bytes 
    For EAP-AKA'-HPQC
        MK is 384 bits = 48 bytes 
        MK_HYBRID is 1280 = 160 bytes

    Key is IK' + CK'
    */

    size_t key_len = OGS_KEY_LEN*2;

    uint8_t key_prf[key_len];
    memcpy(key_prf, ik_prime, OGS_KEY_LEN);
    memcpy(key_prf+OGS_KEY_LEN, ck_prime, OGS_KEY_LEN);

    // change prefix to use EAP-AKA'-FS
    const char *prefix = "EAP-AKA'";
    char *supi = ogs_id_get_value(ausf_ue->supi);
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
    uint8_t mk[mk_len];

    ogs_prf_prime(key_prf, key_len, input, input_len, mk, mk_len);

    /* Debug PRF */
    char input_str[OGS_KEYSTRLEN(input_len)];
    ogs_hex_to_ascii(input, sizeof(input),
        input_str, sizeof(input_str));

    char mk_string[OGS_KEYSTRLEN(mk_len)];
    ogs_hex_to_ascii(mk, sizeof(mk),
        mk_string, sizeof(mk_string));
    
    char key_prf_string[OGS_KEYSTRLEN(key_len)];
    ogs_hex_to_ascii(key_prf, sizeof(key_prf),
        key_prf_string, sizeof(key_prf_string));

    ogs_debug("[EAP_AKA_PRIME][NEW ENGINE] Input : [%s]", input_str);
    ogs_debug("[EAP_AKA_PRIME][NEW ENGINE] MK : [%s]", mk_string);
    /* End Debug PRF*/

    memcpy(ausf_ue->k_aut,mk+16,OGS_SHA256_DIGEST_SIZE);

    // need to calculate k_ausf after eap-resp success, because in FS extension, this key
    // derived from MK_ECDHE, and for HPQC it derived from MK_PQ_SHARED
    memcpy(ausf_ue->kausf,mk+144,OGS_SHA256_DIGEST_SIZE);
    
    ogs_debug("[EAP_AKA_PRIME] Serving Network : [%s]", ausf_ue->serving_network_name);


    
    // FS Extension 

    /*
    // HPQC
    // Generate ECDHE public key pair
    // generate private key
    uint8_t priv_key_ecdhe[32];
    
    priv_key_ecdhe[0] &= 248;
    priv_key_ecdhe[31] &= 127;
    priv_key_ecdhe[31] |= 64;

    static const uint8_t curve25519_basepoint[32] = {9};
    
    uint8_t pub_key_ecdhe[32];

    curve25519_donna(pub_key_ecdhe, priv_key_ecdhe, curve25519_basepoint);

    memcpy(ausf_ue->hnPrivateKey,priv_key_ecdhe,32);

    // Debug ECDHE
    char priv_key_ecdhe_string[OGS_KEYSTRLEN(32)];
    char curve25519_basepoint_string[OGS_KEYSTRLEN(32)];
    char pub_key_ecdhe_string[OGS_KEYSTRLEN(32)];

    ogs_hex_to_ascii(priv_key_ecdhe, sizeof(priv_key_ecdhe),
        priv_key_ecdhe_string, sizeof(priv_key_ecdhe_string));
    ogs_hex_to_ascii(curve25519_basepoint, sizeof(curve25519_basepoint),
        curve25519_basepoint_string, sizeof(curve25519_basepoint_string));
    ogs_hex_to_ascii(pub_key_ecdhe, sizeof(pub_key_ecdhe),
        pub_key_ecdhe_string, sizeof(pub_key_ecdhe_string));    
    ogs_debug("[EAP_AKA_PRIME][NEW ENGINE] Private Key ECDHE : [%s]", priv_key_ecdhe_string);
    ogs_debug("[EAP_AKA_PRIME][NEW ENGINE] Curve25519 basepoint : [%s]", curve25519_basepoint_string);
    ogs_debug("[EAP_AKA_PRIME][NEW ENGINE] Public Key ECDHE : [%s]", pub_key_ecdhe_string);
    // End debug ECDHE

    // Start ML-KEM  

    ogs_debug("[EAP_AKA_PRIME][HPQC][ML-KEM] OQS_KEM_ml_kem_768_length_public_key: [%d]",OQS_KEM_ml_kem_768_length_public_key);
    ogs_debug("[EAP_AKA_PRIME][HPQC][ML-KEM] OQS_KEM_ml_kem_768_length_secret_key: [%d]",OQS_KEM_ml_kem_768_length_secret_key);
    ogs_debug("[EAP_AKA_PRIME][HPQC][ML-KEM] OQS_KEM_ml_kem_768_length_ciphertext: [%d]",OQS_KEM_ml_kem_768_length_ciphertext);
    ogs_debug("[EAP_AKA_PRIME][HPQC][ML-KEM] OQS_KEM_ml_kem_768_length_shared_secret: [%d]",OQS_KEM_ml_kem_768_length_shared_secret);
    ogs_debug("[EAP_AKA_PRIME][HPQC][ML-KEM] OQS_KEM_ml_kem_768_length_shared_secret: [%d]",OQS_KEM_ml_kem_768_length_shared_secret);

    // Start X-WING Key Generation 

    //uint8_t sk[32];
    uint8_t expanded[96];

    //sk[0] &= 248;
    //sk[31] &= 127;
    //sk[31] |= 64;

    // use test vector 
    uint8_t sk[32] = {
        0x7f, 0x9c, 0x2b, 0xa4, 0xe8, 0x8f, 0x82, 0x7d,
        0x61, 0x60, 0x45, 0x50, 0x76, 0x05, 0x85, 0x3e,
        0xd7, 0x3b, 0x80, 0x93, 0xf6, 0xef, 0xbc, 0x88,
        0xeb, 0x1a, 0x6e, 0xac, 0xfa, 0x66, 0xef, 0x26
    };
    

    OQS_SHA3_shake256(expanded, 96, sk, 32);

    char sk_string[OGS_KEYSTRLEN(32)];
    char expanded_string[OGS_KEYSTRLEN(96)];

    ogs_hex_to_ascii(sk, sizeof(sk),
        sk_string, sizeof(sk_string));
    ogs_hex_to_ascii(expanded, sizeof(expanded),
        expanded_string, sizeof(expanded_string));
    ogs_debug("[EAP_AKA_PRIME][HPQC][ML-KEM] sk : [%s]", sk_string);
    ogs_debug("[EAP_AKA_PRIME][HPQC][ML-KEM] expanded : [%s]", expanded_string);

    //(pk_M, sk_M) = ML-KEM-768.KeyGen_internal(expanded[0:32], expanded[32:64])

    uint8_t public_key[OQS_KEM_ml_kem_768_length_public_key];
	uint8_t secret_key[OQS_KEM_ml_kem_768_length_secret_key];
    uint8_t seed[64];


    memcpy(seed, expanded, 64);
    OQS_KEM_ml_kem_768_keypair_derand(public_key,secret_key, seed);


    char public_key_string[OGS_KEYSTRLEN(OQS_KEM_ml_kem_768_length_public_key)];
    char secret_key_string[OGS_KEYSTRLEN(OQS_KEM_ml_kem_768_length_secret_key)];
    char seed_string[OGS_KEYSTRLEN(64)];

    ogs_hex_to_ascii(public_key, sizeof(public_key),
        public_key_string, sizeof(public_key_string));
    ogs_hex_to_ascii(secret_key, sizeof(secret_key),
        secret_key_string, sizeof(secret_key_string));
    ogs_hex_to_ascii(seed, sizeof(seed),
        seed_string, sizeof(seed_string));

    ogs_debug("[EAP_AKA_PRIME][HPQC][ML-KEM] Seed : [%s]", seed_string);
    ogs_debug("[EAP_AKA_PRIME][HPQC][ML-KEM] Public Key : [%s]", public_key_string);
    ogs_debug("[EAP_AKA_PRIME][HPQC][ML-KEM] Secret Key : [%s]", secret_key_string);
    

    
    //sk_X = expanded[64:96]
    //pk_X = X25519(sk_X, X25519_BASE)
    

    uint8_t sk_X[32];
    uint8_t pk_X[32];
    static const uint8_t x25519_base[32] = {9};

    memcpy(sk_X, expanded+64, 32);

    curve25519_donna(pk_X, sk_X, x25519_base);

    //return (sk_M, sk_X, pk_M, pk_X)
    // return sk, concat(pk_M, pk_X)

    uint8_t decapsulation_key[32];
    uint8_t encapsulation_key[1216];

    memcpy(decapsulation_key, sk, 32);
    memcpy(encapsulation_key, public_key, 1184);
    memcpy(encapsulation_key+1184, pk_X , 32);


    // debug
    char decapsulation_key_string[OGS_KEYSTRLEN(32)];
    char encapsulation_key_string[OGS_KEYSTRLEN(1216)];


    ogs_hex_to_ascii(decapsulation_key, sizeof(decapsulation_key),
        decapsulation_key_string, sizeof(decapsulation_key_string));
    ogs_hex_to_ascii(encapsulation_key, sizeof(encapsulation_key),
        encapsulation_key_string, sizeof(encapsulation_key_string));

    ogs_debug("[EAP_AKA_PRIME][HPQC][X-Wing] Decapsulation Key : [%s]", decapsulation_key_string);
    ogs_debug("[EAP_AKA_PRIME][HPQC][X-Wing] Encapsulation Key : [%s]", encapsulation_key_string);

    memcpy(ausf_ue->sk_xwing,sk,32);

    */

    // PQC 

    ogs_debug("[EAP_AKA_PRIME][PQC][ML-KEM] OQS_KEM_ml_kem_768_length_public_key: [%d]",OQS_KEM_ml_kem_768_length_public_key);
    ogs_debug("[EAP_AKA_PRIME][PQC][ML-KEM] OQS_KEM_ml_kem_768_length_secret_key: [%d]",OQS_KEM_ml_kem_768_length_secret_key);
    ogs_debug("[EAP_AKA_PRIME][PQC][ML-KEM] OQS_KEM_ml_kem_768_length_ciphertext: [%d]",OQS_KEM_ml_kem_768_length_ciphertext);
    ogs_debug("[EAP_AKA_PRIME][PQC][ML-KEM] OQS_KEM_ml_kem_768_length_shared_secret: [%d]",OQS_KEM_ml_kem_768_length_shared_secret);
    ogs_debug("[EAP_AKA_PRIME][PQC][ML-KEM] OQS_KEM_ml_kem_768_length_shared_secret: [%d]",OQS_KEM_ml_kem_768_length_shared_secret);


    uint8_t public_key[OQS_KEM_ml_kem_768_length_public_key]; // 1184
    uint8_t secret_key[OQS_KEM_ml_kem_768_length_secret_key]; // 2400
    

    OQS_KEM_ml_kem_768_keypair(public_key, secret_key);

    memcpy(ausf_ue->sk,secret_key,2400);

    // debug ML_KEM
    char public_key_string[OGS_KEYSTRLEN(OQS_KEM_ml_kem_768_length_public_key)];
    char secret_key_string[OGS_KEYSTRLEN(OQS_KEM_ml_kem_768_length_secret_key)];

    ogs_hex_to_ascii(public_key, sizeof(public_key),
        public_key_string, sizeof(public_key_string));
    ogs_hex_to_ascii(secret_key, sizeof(secret_key),
        secret_key_string, sizeof(secret_key_string));

    ogs_debug("[EAP_AKA_PRIME][PQC][ML-KEM] Public Key : [%s]", public_key_string);
    ogs_debug("[EAP_AKA_PRIME][PQC][ML-KEM] Secret Key : [%s]", secret_key_string);
    // end debug ML_KEM
    


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
    //optional
    //uint8_t at_pub_ecdhe[EAP_AKA_ATTRIBUTE_AT_PUB_ECDHE_LENGTH];
    uint8_t at_kdf_fs[EAP_AKA_ATTRIBUTE_AT_KDF_LENGTH]; // 4
    //uint8_t at_pub_hybrid[EAP_AKA_ATTRIBUTE_AT_PUB_HYBRID_LENGTH]; // 1220
    uint8_t at_pub_kem[EAP_AKA_ATTRIBUTE_AT_PUB_KEM_LENGTH]; // 1188
    

    // encode attribute
    eap_aka_encode_attribute(EAP_AKA_ATTRIBUTE_AT_RAND, rand, OGS_RAND_LEN, at_rand);
    eap_aka_encode_attribute(EAP_AKA_ATTRIBUTE_AT_AUTN, autn, OGS_AUTN_LEN, at_autn);
    eap_aka_encode_attribute(EAP_AKA_ATTRIBUTE_AT_KDF, NULL, 0, at_kdf);
    eap_aka_encode_attribute(EAP_AKA_ATTRIBUTE_AT_KDF_INPUT, ausf_ue->serving_network_name, strlen(ausf_ue->serving_network_name), at_kdf_input);
    eap_aka_encode_attribute(EAP_AKA_ATTRIBUTE_AT_MAC, NULL, OGS_RAND_LEN, at_mac);
    //eap_aka_encode_attribute(EAP_AKA_ATTRIBUTE_AT_PUB_ECDHE, pub_key_ecdhe, 32, at_pub_ecdhe);
    //eap_aka_encode_attribute(EAP_AKA_ATTRIBUTE_AT_PUB_HYBRID, encapsulation_key, 1216, at_pub_hybrid);
    eap_aka_encode_attribute(EAP_AKA_ATTRIBUTE_AT_PUB_KEM, public_key, OQS_KEM_ml_kem_768_length_public_key, at_pub_kem);
    eap_aka_encode_attribute(EAP_AKA_ATTRIBUTE_AT_KDF_FS, NULL, 0, at_kdf_fs);


    // append all attribute 
    size_t offset = 0;
    memcpy(data_attribute + offset, at_rand, EAP_AKA_ATTRIBUTE_AT_RAND_LENGTH);
    offset+=EAP_AKA_ATTRIBUTE_AT_RAND_LENGTH;
    memcpy(data_attribute + offset, at_autn, EAP_AKA_ATTRIBUTE_AT_AUTN_LENGTH);
    offset+=EAP_AKA_ATTRIBUTE_AT_AUTN_LENGTH;
    memcpy(data_attribute + offset, at_kdf, EAP_AKA_ATTRIBUTE_AT_KDF_LENGTH);
    offset+=EAP_AKA_ATTRIBUTE_AT_KDF_LENGTH;
    memcpy(data_attribute + offset, at_kdf_fs, EAP_AKA_ATTRIBUTE_AT_KDF_LENGTH);
    offset+=EAP_AKA_ATTRIBUTE_AT_KDF_LENGTH;
    memcpy(data_attribute + offset, at_kdf_input, at_kdf_input_length);
    offset+=at_kdf_input_length;
    //memcpy(data_attribute + offset, at_pub_ecdhe, EAP_AKA_ATTRIBUTE_AT_PUB_ECDHE_LENGTH);
    //offset+=EAP_AKA_ATTRIBUTE_AT_PUB_ECDHE_LENGTH;
    //memcpy(data_attribute + offset, at_pub_hybrid, EAP_AKA_ATTRIBUTE_AT_PUB_HYBRID_LENGTH);
    //offset+=EAP_AKA_ATTRIBUTE_AT_PUB_HYBRID_LENGTH;
    memcpy(data_attribute + offset, at_pub_kem, EAP_AKA_ATTRIBUTE_AT_PUB_KEM_LENGTH);
    offset+=EAP_AKA_ATTRIBUTE_AT_PUB_KEM_LENGTH;
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

    /* Start Debug */
    char new_at_rand_string[OGS_KEYSTRLEN(EAP_AKA_ATTRIBUTE_AT_RAND_LENGTH)];
    char new_at_autn_string[OGS_KEYSTRLEN(EAP_AKA_ATTRIBUTE_AT_AUTN_LENGTH)];
    char new_at_kdf_string[OGS_KEYSTRLEN(EAP_AKA_ATTRIBUTE_AT_KDF_LENGTH)];
    char new_at_kdf_input_string[OGS_KEYSTRLEN(at_kdf_input_length)];
    char new_at_mac_string[OGS_KEYSTRLEN(EAP_AKA_ATTRIBUTE_AT_MAC_LENGTH)];
    char data_attribute_string[OGS_KEYSTRLEN(offset)];
    char eap_request_string[OGS_KEYSTRLEN(eap_request_length)];

    ogs_hex_to_ascii(at_rand, sizeof(at_rand),
        new_at_rand_string, sizeof(new_at_rand_string));
    ogs_hex_to_ascii(at_autn, sizeof(at_autn),
        new_at_autn_string, sizeof(new_at_autn_string));
    ogs_hex_to_ascii(at_kdf, sizeof(at_kdf),
        new_at_kdf_string, sizeof(new_at_kdf_string));
    ogs_hex_to_ascii(at_kdf_input, sizeof(at_kdf_input),
        new_at_kdf_input_string, sizeof(new_at_kdf_input_string));
    ogs_hex_to_ascii(at_mac, sizeof(at_mac),
        new_at_mac_string, sizeof(new_at_mac_string));
    ogs_hex_to_ascii(data_attribute, sizeof(data_attribute),
        data_attribute_string, sizeof(data_attribute_string));
    ogs_hex_to_ascii(eap_request, sizeof(eap_request),
        eap_request_string, sizeof(eap_request_string));

    ogs_debug("[EAP_AKA_PRIME][NEW ENGINE] AT_RAND[%s]", new_at_rand_string);
    ogs_debug("[EAP_AKA_PRIME][NEW ENGINE] AT_AUTN[%s]", new_at_autn_string);
    ogs_debug("[EAP_AKA_PRIME][NEW ENGINE] AT_KDF[%s]", new_at_kdf_string);
    ogs_debug("[EAP_AKA_PRIME][NEW ENGINE] AT_KDF_INPUT[%s]", new_at_kdf_input_string);
    ogs_debug("[EAP_AKA_PRIME][NEW ENGINE] at_kdf_input_length[%ld]", at_kdf_input_length);
    ogs_debug("[EAP_AKA_PRIME][NEW ENGINE] AT_MAC[%s]", new_at_mac_string);
    ogs_debug("[EAP_AKA_PRIME][NEW ENGINE] ATTRIBUTE[%s]", data_attribute_string);
    ogs_debug("[EAP_AKA_PRIME][NEW ENGINE] offset[%ld]", offset);
    ogs_debug("[EAP_AKA_PRIME][NEW ENGINE] EAP Request[%s]", eap_request_string);
    ogs_debug("[EAP_AKA_PRIME][NEW ENGINE] EAP Request Length[%ld]", strlen(eap_request_string));
    ogs_debug("[EAP_AKA_PRIME][NEW ENGINE] EAP Request(Base64)[%s]", eap_request_base64);
    ogs_debug("[EAP_AKA_PRIME][NEW ENGINE] EAP Request(Base64) Length[%ld]", strlen(eap_request_base64));
    /* End of Debug*/


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


        // calculate mk_ecdhe
        // if FS extension is used, it need to compute MK_ECDHE. this information received at ausf-handler


        /*
        // X-Wing 
        uint8_t ct_M[1088];
        uint8_t ct_X[32];
        uint8_t ss_M[32];
        uint8_t ss_X[32];

        memcpy(ct_M,ausf_ue->ct_xwing, 1088);
        memcpy(ct_X,ausf_ue->ct_xwing+1088, 32);



        // Decapsulate key (sk)
        uint8_t expanded[96];
    
        OQS_SHA3_shake256(expanded, 96, ausf_ue->sk_xwing, 32);
    
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

        uint8_t shared_key[32];

        OQS_SHA3_sha3_256(shared_key,combiner_output,134);


        // print 
        //char shared_secret_string[OGS_KEYSTRLEN(32)];
        
        // ogs_hex_to_ascii(shared_secret, sizeof(shared_secret),
        // shared_secret_string, sizeof(shared_secret_string));
        // ogs_hex_to_ascii(ausf_ue->ct_xwing, sizeof(ausf_ue->ct_xwing),
        // ct_xwing_string, sizeof(ct_xwing_string));
        // ogs_hex_to_ascii(ausf_ue->sk_xwing, sizeof(ausf_ue->sk_xwing),
        // sk_xwing_string, sizeof(sk_xwing_string));

        
        // ogs_debug("[EAP_AKA_PRIME][HPQC][X-Wing][ML_KEM] Shared Secret Key: [%s]", shared_key_string_first);
        // ogs_debug("[EAP_AKA_PRIME][HPQC][X-Wing][ML_KEM] sk X-Wing: [%s]", sk_xwing_string);
        // ogs_debug("[EAP_AKA_PRIME][HPQC][X-Wing][ML_KEM] ct X-Wing : [%s]", ct_xwing_string);

        */

        // PQC (ML_KEM)

        uint8_t ct[1088];        
        uint8_t shared_secret_key[32];

        memcpy(ct, ausf_ue->ct, 1088);

        OQS_KEM_ml_kem_768_decaps(shared_secret_key, ausf_ue->ct, ausf_ue->sk);

        /*
        
        size_t key_len = OGS_KEY_LEN*2;

        uint8_t key_prf[key_len];
        memcpy(key_prf, ik_prime, OGS_KEY_LEN);
        memcpy(key_prf+OGS_KEY_LEN, ck_prime, OGS_KEY_LEN);
        */
        size_t key_len = 64;

        uint8_t key_prf[key_len];
        memcpy(key_prf, ausf_ue->ik_prime, 16);
        memcpy(key_prf+16, ausf_ue->ck_prime, 16);
        memcpy(key_prf+32, shared_secret_key, 32);

        // change prefix to use EAP-AKA'-FS
        const char *prefix = "EAP-AKA' FS";
        char *supi = ogs_id_get_value(ausf_ue->supi);
        size_t input_len = strlen(prefix) + strlen(supi) + 1088; // ct length 

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
            input[pos] = ct[i];  
            pos++;
        }


        // output master key (MK) ECDHE is 1280 bits = 160 bytes
        size_t mk_pq_shared_secret_len = 160; 
        uint8_t mk_pq_shared_secret[mk_pq_shared_secret_len];

        ogs_prf_prime(key_prf, key_len, input, input_len, mk_pq_shared_secret, mk_pq_shared_secret_len);

        memcpy(ausf_ue->kausf,mk_pq_shared_secret+96,32);

        /* Debug ECDHE*/
        /*
        char ue_public_key_string[OGS_KEYSTRLEN(32)];
        char hn_private_key_string[OGS_KEYSTRLEN(32)];
        char shared_key_string[OGS_KEYSTRLEN(32)];
        char prf_key_string[OGS_KEYSTRLEN(64)];
        char input_prf_string[OGS_KEYSTRLEN(input_len)];

        char mk_ecdhe_string[OGS_KEYSTRLEN(160)];
        char kausf_string[OGS_KEYSTRLEN(32)];

        ogs_hex_to_ascii(ausf_ue->uePublicKey, sizeof(ausf_ue->uePublicKey),
            ue_public_key_string, sizeof(ue_public_key_string));
        ogs_hex_to_ascii(ausf_ue->hnPrivateKey, sizeof(ausf_ue->hnPrivateKey),
            hn_private_key_string, sizeof(hn_private_key_string));
        ogs_hex_to_ascii(shared_key, sizeof(shared_key),
            shared_key_string, sizeof(shared_key_string));
        ogs_hex_to_ascii(key_prf, sizeof(key_prf),
            prf_key_string, sizeof(prf_key_string));

        ogs_hex_to_ascii(input, sizeof(input),
            input_prf_string, sizeof(input_prf_string));
        ogs_hex_to_ascii(mk_ecdhe, sizeof(mk_ecdhe),
            mk_ecdhe_string, sizeof(mk_ecdhe_string));
        ogs_hex_to_ascii(ausf_ue->kausf, sizeof(ausf_ue->kausf),
            kausf_string, sizeof(kausf_string));
            
        ogs_debug("[EAP_AKA_PRIME][NEW ENGINE] Public Key UE : [%s]", ue_public_key_string);
        ogs_debug("[EAP_AKA_PRIME][NEW ENGINE] Private Key HN : [%s]", hn_private_key_string);
        ogs_debug("[EAP_AKA_PRIME][NEW ENGINE] Shared Secret Key ECDHE : [%s]", shared_key_string);
        ogs_debug("[EAP_AKA_PRIME][NEW ENGINE] Input PRF : [%s]", input_prf_string);
        ogs_debug("[EAP_AKA_PRIME][NEW ENGINE] Key PRF : [%s]", prf_key_string);
        ogs_debug("[EAP_AKA_PRIME][NEW ENGINE] MK ECDHE : [%s]", mk_ecdhe_string);
        ogs_debug("[EAP_AKA_PRIME][NEW ENGINE] K_AUSF : [%s]", kausf_string);
        */
        /* End debug ECDHE*/

        /*
        // Debug X-WING
        char ciphertext_string[OGS_KEYSTRLEN(1120)];
        char shared_key_string[OGS_KEYSTRLEN(32)];
        char mk_ecdhe_string[OGS_KEYSTRLEN(160)];
        char kausf_string[OGS_KEYSTRLEN(32)];

        ogs_hex_to_ascii(ausf_ue->ct_xwing, sizeof(ausf_ue->ct_xwing),
            ciphertext_string, sizeof(ciphertext_string));
        ogs_hex_to_ascii(shared_key, sizeof(shared_key),
            shared_key_string, sizeof(shared_key_string));
        ogs_hex_to_ascii(mk_ecdhe, sizeof(mk_ecdhe),
            mk_ecdhe_string, sizeof(mk_ecdhe_string));
        ogs_hex_to_ascii(ausf_ue->kausf, sizeof(ausf_ue->kausf),
            kausf_string, sizeof(kausf_string));


        ogs_debug("[EAP_AKA_PRIME][HPQC][X-Wing] Ciphertext: [%s]", ciphertext_string);
        ogs_debug("[EAP_AKA_PRIME][HPQC][X-Wing] Shared Secret Key: [%s]", shared_key_string);
        ogs_debug("[EAP_AKA_PRIME][HPQC][X-Wing] MK ECDHE : [%s]", mk_ecdhe_string);
        ogs_debug("[EAP_AKA_PRIME][HPQC][X-Wing] K_AUSF : [%s]", kausf_string);
        // End debug X-WING
        */ 
        // Debug PQC ML_KEM 
        char ct_string[OGS_KEYSTRLEN(1088)];
        char sk_string[OGS_KEYSTRLEN(2400)];
        char shared_secret_key_string[OGS_KEYSTRLEN(32)];
        char mk_pq_shared_secret_string[OGS_KEYSTRLEN(160)];
        char kausf_string[OGS_KEYSTRLEN(32)];

        ogs_hex_to_ascii(ausf_ue->ct, sizeof(ausf_ue->ct),
            ct_string, sizeof(ct_string));
        ogs_hex_to_ascii(ausf_ue->sk, sizeof(ausf_ue->sk),
            sk_string, sizeof(sk_string));
        ogs_hex_to_ascii(shared_secret_key, sizeof(shared_secret_key),
            shared_secret_key_string, sizeof(shared_secret_key_string));
        ogs_hex_to_ascii(mk_pq_shared_secret, sizeof(mk_pq_shared_secret),
            mk_pq_shared_secret_string, sizeof(mk_pq_shared_secret_string));
        ogs_hex_to_ascii(ausf_ue->kausf, sizeof(ausf_ue->kausf),
            kausf_string, sizeof(kausf_string));

        ogs_debug("[EAP_AKA_PRIME][PQC][ML_KEM] Ciphertext: [%s]", ct_string);
        ogs_debug("[EAP_AKA_PRIME][PQC][ML_KEM] Secret key: [%s]", sk_string);
        ogs_debug("[EAP_AKA_PRIME][PQC][ML_KEM] Shared Secret Key: [%s]", shared_secret_key_string);
        ogs_debug("[EAP_AKA_PRIME][PQC][ML_KEM] MK_PQ_SHARED_SECRET : [%s]", mk_pq_shared_secret_string);
        ogs_debug("[EAP_AKA_PRIME][PQC][ML_KEM] K_AUSF : [%s]", kausf_string);
        // END Debug PQC ML_KEM 
        


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