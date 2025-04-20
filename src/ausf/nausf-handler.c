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
    //ogs_nas_eap_message_t *eap_message = NULL;

    //char eap_payload = NULL;

    //char *res_string = NULL;
    //int8_t res[OGS_KEYSTRLEN(OGS_MAX_RES_LEN)];

    int r;
    int len;

    ogs_assert(ausf_ue);
    ogs_assert(stream);
    ogs_assert(recvmsg);

    EapSession = recvmsg->EapSession;


    ogs_debug("[EAP_AKA_PRIME] eap_payload [%s]",EapSession->eap_payload);

    uint8_t eap_payload[OGS_MAX_EAP_PAYLOAD_LEN];

    len = ogs_base64_decode_binary(eap_payload,EapSession->eap_payload);
    
    if (len == 0)
        ogs_error("[EAP_AKA_PRIME] eap_payload not decoded ");

    ogs_debug("[EAP_AKA_PRIME] eap_payload len decoded %d",len);
    //ogs_debug("[EAP_AKA_PRIME] eap_payload [%s]",eap_payload); 

    char eap_payload_string[len*2+1];
    ogs_hex_to_ascii(eap_payload, sizeof(eap_payload),
            eap_payload_string, sizeof(eap_payload_string));
    ogs_debug("[EAP_AKA_PRIME] eap_payload [%s]",eap_payload_string); 

    size_t pos = 0;

    ogs_debug("[EAP_AKA_PRIME] Response [%02x]",eap_payload[pos++]);
    ogs_debug("[EAP_AKA_PRIME] Identifier [%02x]",eap_payload[pos++]);
    pos = pos + 2;
    ogs_debug("[EAP_AKA_PRIME] EAP_AKA_PRIME IDENTIFIER [%02x]",eap_payload[pos++]);
    ogs_debug("[EAP_AKA_PRIME] AKA-CHALLENGE [%02x]",eap_payload[pos++]);
    pos = pos + 2; //reserve bit 
    ogs_debug("[EAP_AKA_PRIME] AT_RES(3) [%02x]",eap_payload[pos++]);
    ogs_debug("[EAP_AKA_PRIME] AT_RES length [%02x]",eap_payload[pos++]);

    uint16_t at_res_length =  (eap_payload[pos] << 8 ) | eap_payload[pos+1];
    ogs_debug("[EAP_AKA_PRIME] AT_RES length data [%u]",at_res_length);
    pos = pos + 2;

    uint8_t res[8] ;
    char res_string[8*2+1];
    
    memcpy(res, &eap_payload[pos],8);

    ogs_hex_to_ascii(res, sizeof(res),
        res_string, sizeof(res_string));

    ogs_debug("[EAP_AKA_PRIME] AT_RES data [%s]",res_string);
    pos = pos + 8;

    ogs_debug("[EAP_AKA_PRIME] AT_MAC(11) [%02x]",eap_payload[pos++]);
    ogs_debug("[EAP_AKA_PRIME] AT_MAC length (5) [%02x]",eap_payload[pos++]);
    pos = pos + 2 ; //reserve bytes
    
    uint8_t mac[16];
    char mac_string[16*2+1];

    memcpy(mac, &eap_payload[pos],16);
    ogs_hex_to_ascii(mac, sizeof(mac),
        mac_string, sizeof(mac_string));

    ogs_debug("[EAP_AKA_PRIME] AT_MAC data [%s]",mac_string);
    pos = pos + 16;

    ogs_debug("[EAP_AKA_PRIME] AT_KDF (24) [%02x]",eap_payload[pos++]);
    ogs_debug("[EAP_AKA_PRIME] AT_KDF length (5) [%02x]",eap_payload[pos++]);
    uint16_t at_kdf_value =  (eap_payload[pos] << 8 ) | eap_payload[pos+1];
    ogs_debug("[EAP_AKA_PRIME] AT_KDF Value [%u]",at_kdf_value);


    if (memcmp(res, ausf_ue->xres, OGS_MAX_RES_LEN/2) != 0) {
        ogs_log_hexdump(OGS_LOG_WARN, res, OGS_MAX_RES_LEN);
        ogs_log_hexdump(OGS_LOG_WARN, ausf_ue->xres, OGS_MAX_RES_LEN);

        ausf_ue->auth_result = OpenAPI_auth_result_AUTHENTICATION_FAILURE;
    } else {
        ogs_debug("[EAP_AKA_PRIME] RES MATCH!");
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
