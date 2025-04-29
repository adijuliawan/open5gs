/*
 * Copyright (C) 2019,2020 by Sukchan Lee <acetcom@gmail.com>
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

#include "sbi-path.h"
#include "nnrf-handler.h"
#include "nausf-handler.h"
#include "eap/eap.h"

bool ausf_nausf_auth_handle_authenticate(ausf_ue_t *ausf_ue,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    OpenAPI_authentication_info_t *AuthenticationInfo = NULL;
    char *serving_network_name = NULL;
    int r;

    ogs_assert(ausf_ue);
    ogs_assert(stream);
    ogs_assert(recvmsg);

    AuthenticationInfo = recvmsg->AuthenticationInfo;
    if (!AuthenticationInfo) {
        ogs_error("[%s] No AuthenticationInfo", ausf_ue->suci);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No AuthenticationInfo", ausf_ue->suci, NULL));
        return false;
    }

    serving_network_name = AuthenticationInfo->serving_network_name;
    if (!serving_network_name) {
        ogs_error("[%s] No servingNetworkName", ausf_ue->suci);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No servingNetworkName", ausf_ue->suci, NULL));
        return false;
    }

    if (ausf_ue->serving_network_name)
        ogs_free(ausf_ue->serving_network_name);
    ausf_ue->serving_network_name = ogs_strdup(serving_network_name);
    ogs_assert(ausf_ue->serving_network_name);

    r = ausf_sbi_discover_and_send(
            OGS_SBI_SERVICE_TYPE_NUDM_UEAU, NULL,
            ausf_nudm_ueau_build_get,
            ausf_ue, stream, AuthenticationInfo->resynchronization_info);
    ogs_expect(r == OGS_OK);
    ogs_assert(r != OGS_ERROR);

    return true;
}

bool ausf_nausf_auth_handle_authenticate_eap_session(ausf_ue_t *ausf_ue,
    ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    OpenAPI_eap_session_t *EapSession  = NULL;

    int r;

    ogs_assert(ausf_ue);
    ogs_assert(stream);
    ogs_assert(recvmsg);

    EapSession = recvmsg->EapSession;


    uint8_t eap_response_decoded[OGS_MAX_EAP_PAYLOAD_LEN];
    size_t eap_reponse_len = ogs_base64_decode_binary(eap_response_decoded,EapSession->eap_payload);
    uint8_t eap_response_mac_input[eap_reponse_len];
    
    if (eap_reponse_len == 0)
        ogs_error("[EAP_AKA_PRIME] eap_payload not decoded ");

    uint8_t at_res[8];
    uint8_t at_mac[16];
    uint8_t at_pub_ecdhe[32];
    uint8_t at_pub_hybrid[1120];

    /*
    RFC 9678 - Section 6.5.4 EAP-Response/AKA'-Challenge

    If the Server has proposed the use of the extension specified in this 
    protocol, but the Peer ignores and continues the basic EAP-AKA' 
    authentication, the Server makes a policy decision of whether this is 
    allowed. If this is allowed, it continues the EAP-AKA' authentication 
    to completion. If it is not allowed, the Server MUST behave as if 
    authentication failed.
    */
    // Policy : Not Allowed 

    uint8_t xmac[OGS_SHA256_DIGEST_SIZE];

    //create new copy of eap_request, clean at_mac for integrity check (at_mac)
    eap_aka_decode_attribute(EAP_AKA_ATTRIBUTE_AT_RES, eap_response_decoded, eap_reponse_len, at_res);
    eap_aka_decode_attribute(EAP_AKA_ATTRIBUTE_AT_MAC, eap_response_decoded, eap_reponse_len, at_mac);

    size_t fs_extension_status = eap_aka_decode_attribute(EAP_AKA_ATTRIBUTE_AT_PUB_ECDHE, eap_response_decoded, eap_reponse_len, at_pub_ecdhe);
    size_t hpqc_extension_status = eap_aka_decode_attribute(EAP_AKA_ATTRIBUTE_AT_PUB_HYBRID, eap_response_decoded, eap_reponse_len, at_pub_hybrid);

    eap_aka_clean_mac(EAP_AKA_ATTRIBUTE_AT_MAC, eap_response_decoded, eap_reponse_len, eap_response_mac_input);    

    //mac calculation 
    ogs_hmac_sha256(ausf_ue->k_aut, 32, eap_response_mac_input, eap_reponse_len, xmac, OGS_SHA256_DIGEST_SIZE);

    if(EAP_AKA_PRIME_EXTENSION==1 && fs_extension_status == 0){
        // No AT_PUB_ECDHE in EAP-Response 
        ogs_error("AT_PUB_ECDHE not found in EAP Response");
        ausf_ue->auth_result = OpenAPI_auth_result_AUTHENTICATION_FAILURE;
    }
    else if(EAP_AKA_PRIME_EXTENSION==2 && hpqc_extension_status == 0){
        // No AT_PUB_HYBRID in EAP Ressponse
        ogs_error("AT_PUB_HYBRID not found in EAP Response");
        ausf_ue->auth_result = OpenAPI_auth_result_AUTHENTICATION_FAILURE;
    }
    else{
        // now check AT_MAC and AT_RES 
        if (memcmp(xmac, at_mac, OGS_SHA256_DIGEST_SIZE/2) != 0 ) {
            ogs_log_hexdump(OGS_LOG_WARN, xmac, OGS_SHA256_DIGEST_SIZE);
            ogs_log_hexdump(OGS_LOG_WARN, at_mac, OGS_SHA256_DIGEST_SIZE/2);
            ogs_error("MAC Failure!");
    
            ausf_ue->auth_result = OpenAPI_auth_result_AUTHENTICATION_FAILURE;
        } else if (memcmp(at_res, ausf_ue->xres, OGS_MAX_RES_LEN/2) != 0) {
            ogs_log_hexdump(OGS_LOG_WARN, at_res, OGS_MAX_RES_LEN);
            ogs_log_hexdump(OGS_LOG_WARN, ausf_ue->xres, OGS_MAX_RES_LEN);
    
            ausf_ue->auth_result = OpenAPI_auth_result_AUTHENTICATION_FAILURE;
        } else {
            ausf_ue->auth_result = OpenAPI_auth_result_AUTHENTICATION_SUCCESS;

            // check extension 
            if(EAP_AKA_PRIME_EXTENSION==1){
                memcpy(ausf_ue->uePublicKey,at_pub_ecdhe,32);
            }
            else if(EAP_AKA_PRIME_EXTENSION==2){
                memcpy(ausf_ue->ct_xwing,at_pub_hybrid,1120);
            }
    
        }

    }
    

    r = ausf_sbi_discover_and_send(
            OGS_SBI_SERVICE_TYPE_NUDM_UEAU, NULL,
            ausf_nudm_ueau_build_result_confirmation_inform,
            ausf_ue, stream, NULL);
    ogs_expect(r == OGS_OK);
    ogs_assert(r != OGS_ERROR);

    return true;
}

bool ausf_nausf_auth_handle_authenticate_confirmation(ausf_ue_t *ausf_ue,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    OpenAPI_confirmation_data_t *ConfirmationData = NULL;
    char *res_star_string = NULL;
    uint8_t res_star[OGS_KEYSTRLEN(OGS_MAX_RES_LEN)];
    int r;

    ogs_assert(ausf_ue);
    ogs_assert(stream);
    ogs_assert(recvmsg);

    ConfirmationData = recvmsg->ConfirmationData;
    if (!ConfirmationData) {
        ogs_error("[%s] No ConfirmationData", ausf_ue->suci);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No ConfirmationData", ausf_ue->suci, NULL));
        return false;
    }

    res_star_string = ConfirmationData->res_star;
    if (!res_star_string) {
        ogs_error("[%s] No ConfirmationData.resStar", ausf_ue->suci);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No ConfirmationData.resStar", ausf_ue->suci, NULL));
        return false;
    }

    ogs_ascii_to_hex(res_star_string, strlen(res_star_string),
            res_star, sizeof(res_star));

    if (memcmp(res_star, ausf_ue->xres_star, OGS_MAX_RES_LEN) != 0) {
        ogs_log_hexdump(OGS_LOG_WARN, res_star, OGS_MAX_RES_LEN);
        ogs_log_hexdump(OGS_LOG_WARN, ausf_ue->xres_star, OGS_MAX_RES_LEN);

        ausf_ue->auth_result = OpenAPI_auth_result_AUTHENTICATION_FAILURE;
    } else {
        ausf_ue->auth_result = OpenAPI_auth_result_AUTHENTICATION_SUCCESS;
    }

    r = ausf_sbi_discover_and_send(
            OGS_SBI_SERVICE_TYPE_NUDM_UEAU, NULL,
            ausf_nudm_ueau_build_result_confirmation_inform,
            ausf_ue, stream, NULL);
    ogs_expect(r == OGS_OK);
    ogs_assert(r != OGS_ERROR);

    return true;
}

bool ausf_nausf_auth_handle_authenticate_delete(ausf_ue_t *ausf_ue,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    int r;

    ogs_assert(ausf_ue);
    ogs_assert(stream);
    ogs_assert(recvmsg);

    r = ausf_sbi_discover_and_send(
            OGS_SBI_SERVICE_TYPE_NUDM_UEAU, NULL,
            ausf_nudm_ueau_build_auth_removal_ind,
            ausf_ue, stream, NULL);
    ogs_expect(r == OGS_OK);
    ogs_assert(r != OGS_ERROR);

    return true;
}
