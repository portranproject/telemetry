#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <NGAP_AMF-TNLAssociationToAddList.h>
#include <NGAP_AMF-TNLAssociationToRemoveList.h>
#include <NGAP_AMF-UE-NGAP-ID.h>
#include <NGAP_AMFName.h>
#include <NGAP_CPTransportLayerInformation.h>
#include <NGAP_Cause.h>
#include <NGAP_CoreNetworkAssistanceInformationForInactive.h>
#include <NGAP_FiveG-S-TMSI.h>
#include <NGAP_GUAMI.h>
#include <NGAP_NAS-PDU.h>
#include <NGAP_NGAP-PDU.h>
#include <NGAP_NR-CGI.h>
#include <NGAP_OverloadResponse.h>
#include <NGAP_OverloadStartNSSAIList.h>
#include <NGAP_PDUSessionResourceModifyListModReq.h>
#include <NGAP_PDUSessionResourceSetupListCxtReq.h>
#include <NGAP_PDUSessionResourceSetupListSUReq.h>
#include <NGAP_ProcedureCode.h>
#include <NGAP_ProtocolIE-Field.h>
#include <NGAP_ProtocolIE-ID.h>
#include <NGAP_ProtocolIE-SingleContainer.h>
#include <NGAP_RAN-UE-NGAP-ID.h>
#include <NGAP_RRCEstablishmentCause.h>
#include <NGAP_RRCInactiveTransitionReportRequest.h>
#include <NGAP_RRCState.h>
#include <NGAP_ResetAll.h>
#include <NGAP_ResetType.h>
#include <NGAP_ServedGUAMIItem.h>
#include <NGAP_ServedGUAMIList.h>
#include <NGAP_TrafficLoadReductionIndication.h>
#include <NGAP_UE-NGAP-ID-pair.h>
#include <NGAP_UE-NGAP-IDs.h>
#include <NGAP_UE-associatedLogicalNG-connectionItem.h>
#include <NGAP_UE-associatedLogicalNG-connectionList.h>
#include <NGAP_UERetentionInformation.h>
#include <NGAP_UserLocationInformation.h>
#include <NGAP_UserLocationInformationNR.h>
#include <BIT_STRING.h>
#include <INTEGER.h>
#include <NativeEnumerated.h>
#include <NativeInteger.h>
#include <OCTET_STRING.h>
#include <asn_SEQUENCE_OF.h>
#include <constr_CHOICE.h>

#include "ap.h"

// asn1c 스택 사용 상한 256KB
#define DECODE_MAX_STACK_BYTES (256 * 1024)

// ngap_internal: ngap_msg.internal 이 가리키는 ngap.c 전용 상태. ngap_release 가 해제
//
//   struct ngap_msg (호출자)        struct ngap_internal (힙)
//   +--------------+                +------------------+
//   | internal -------------------> | pdu -------------------> asn1c 트리
//   +--------------+                | nas_ies ---------------> struct ngap_nas 배열
//                                   | tnla_add_ipv4 ---------> uint32_t 배열 (tnla_remove_ipv4 동일)
//                                   | reset_ues -------------> struct ngap_reset_ue 배열
//                                   +------------------+
//
//   ngap_msg 의 nas_ies, tnla_*_ipv4, reset_ues = 위 배열과 같은 주소 (const)
//   nas_ies[i].data, amf_name                   = asn1c 트리 안의 바이트 (복사 없음)
struct ngap_internal {
	NGAP_NGAP_PDU_t *pdu;
	struct ngap_nas *nas_ies;
	int nas_ie_capacity;
	uint32_t *tnla_add_ipv4;
	uint32_t *tnla_remove_ipv4;
	struct ngap_reset_ue *reset_ues;
	int reset_ue_capacity;
	// 이 PDU 에서 이미 본 IE. 비트 n = TAKEN_IES[n]. 중복 판정용
	uint32_t seen_ie_mask;
};

// member_by_name: 설명표(type)에서 이름이 name 인 멤버. 없으면 NULL
static const asn_TYPE_member_t *member_by_name(const asn_TYPE_descriptor_t *type, const char *name) {
	for (unsigned i = 0; i < type->elements_count; i++) {
		const char *member_name = type->elements[i].name;
		if (member_name && strcmp(member_name, name) == 0)
			return &type->elements[i];
	}
	return NULL;
}

// member_value_ptr: 구조체 안 멤버 값의 위치. 포인터 멤버가 비어 있으면 NULL
static const void *member_value_ptr(const asn_TYPE_member_t *member, const void *struct_base) {
	const void *value_ptr = (const char *)struct_base + member->memb_offset;
	if (member->flags & ATF_POINTER)
		value_ptr = *(const void *const *)value_ptr;
	return value_ptr;
}

// choice_selected: CHOICE 에서 고른 갈래와 값 위치. present_out 에 순번(1부터, 0 = 없음)
//   고른 것이 없으면 NULL, *value_out 도 NULL. asn1c 가 모르는 open type 을 버린 자리가 이 상태
static const asn_TYPE_member_t *choice_selected(const asn_TYPE_descriptor_t *type, const void *choice_base, const void **value_out, unsigned *present_out) {
	unsigned present = CHOICE_variant_get_presence(type, choice_base);
	if (present_out)
		*present_out = present;
	*value_out = NULL;
	if (present == 0 || present > type->elements_count)
		return NULL;
	const asn_TYPE_member_t *member = &type->elements[present - 1];
	*value_out = member_value_ptr(member, choice_base);
	return member;
}

// msg_clear: ngap_msg 를 꺼낸 값이 없는 상태로 만듦. 0 이 유효한 값인 네 칸(수립 원인, 감축률, rrc_state, cause)은 -1
static void msg_clear(struct ngap_msg *ngap_msg) {
	memset(ngap_msg, 0, sizeof(*ngap_msg));
	ngap_msg->cause.group = -1;
	ngap_msg->cause.value = -1;
	ngap_msg->rrc_establishment_cause = -1;
	ngap_msg->traffic_load_reduction_percent = -1;
	ngap_msg->rrc_state = -1;
}

// ngap_release: 트리 -> 결과 배열 -> 내부 상태 순으로 해제. 해제한 메모리를 가리키던 포인터는 NULL, 개수는 0.
void ngap_release(struct ngap_msg *ngap_msg) {
	if (!ngap_msg || !ngap_msg->internal)
		return;
	struct ngap_internal *internal = ngap_msg->internal;
	ASN_STRUCT_FREE(asn_DEF_NGAP_NGAP_PDU, internal->pdu);
	free(internal->nas_ies);
	free(internal->tnla_add_ipv4);
	free(internal->tnla_remove_ipv4);
	free(internal->reset_ues);
	free(internal);
	ngap_msg->internal = NULL;
	ngap_msg->nas_ie_count = 0;
	ngap_msg->nas_ies = NULL;
	ngap_msg->tnla_add_count = 0;
	ngap_msg->tnla_add_ipv4 = NULL;
	ngap_msg->tnla_remove_count = 0;
	ngap_msg->tnla_remove_ipv4 = NULL;
	ngap_msg->reset_ue_count = 0;
	ngap_msg->reset_ues = NULL;
	ngap_msg->amf_name = NULL;
	ngap_msg->amf_name_len = 0;
}

// parse_fail: 해석 실패 처리. 잡은 것을 모두 해제하고 ngap_msg 를 값 없는 상태로 되돌림. 반환: result 그대로
static enum ngap_result parse_fail(struct ngap_msg *ngap_msg, enum ngap_result result) {
	ngap_release(ngap_msg);
	msg_clear(ngap_msg);
	return result;
}

// ngap_parse: 입력 검사 -> APER 디코드 -> 남는 바이트 검사 -> PDU 종류 -> 절차 번호, 메시지 이름 -> IE 를 번호로 골라 채움.
//
//   NGAP-PDU
//   +----------+---------------+-------------+---------------------------+
//   | PDU 종류 | procedureCode | criticality | value (message body)      |
//   +----------+---------------+-------------+---------------------------+
//     pdu_type   procedure_code  (읽지 않음)   |
//                                              v  절차 번호 + PDU 종류로 메시지가 정해짐 -> msg_name
//   message body
//   +----------+------+------+------+-----+
//   | IE count | IE 1 | IE 2 | IE 3 | ... |
//   +----------+------+------+------+-----+
//                 |
//                 v  ie_at 으로 하나씩 꺼내 ie_take 가 ngap_msg 필드에 담음
enum ngap_result ngap_parse(const uint8_t *pdu_bytes, size_t len, struct ngap_msg *ngap_msg) {
	if (!ngap_msg)
		return NGAP_DECODE_FAILED;
	msg_clear(ngap_msg);
	if (!pdu_bytes || len == 0)
		return NGAP_DECODE_FAILED;

	struct ngap_internal *internal = calloc(1, sizeof(*internal));
	if (!internal)
		return NGAP_NO_MEMORY;
	ngap_msg->internal = internal;

	unsigned long skipped_count_before = asn_portran_opentype_skipped_count;
	const asn_codec_ctx_t decode_ctx = {.max_stack_size = DECODE_MAX_STACK_BYTES};
	asn_dec_rval_t decoded = aper_decode_complete(&decode_ctx, &asn_DEF_NGAP_NGAP_PDU, (void **)&internal->pdu, pdu_bytes, len);
	// APER PDU 는 바이트 단위로 끝남. len 을 정확히 다 쓰지 않았으면 뒤에 다른 바이트가 붙었거나 길이 필드가 깨진 것
	bool is_whole_pdu = decoded.code == RC_OK && decoded.consumed == len;
	if (!is_whole_pdu)
		return parse_fail(ngap_msg, NGAP_DECODE_FAILED);

	const void *message = NULL;
	unsigned pdu_present = 0;
	const asn_TYPE_member_t *message_member = choice_selected(&asn_DEF_NGAP_NGAP_PDU, internal->pdu, &message, &pdu_present);
	if (!message_member || !message)
		return parse_fail(ngap_msg, NGAP_UNKNOWN_MESSAGE);
	enum ngap_pdu_type pdu_type;
	switch (pdu_present) {
	case NGAP_NGAP_PDU_PR_initiatingMessage:
		pdu_type = NGAP_PDU_INITIATING;
		break;
	case NGAP_NGAP_PDU_PR_successfulOutcome:
		pdu_type = NGAP_PDU_SUCCESSFUL;
		break;
	case NGAP_NGAP_PDU_PR_unsuccessfulOutcome:
		pdu_type = NGAP_PDU_UNSUCCESSFUL;
		break;
	default:
		return parse_fail(ngap_msg, NGAP_UNKNOWN_MESSAGE);
	}

	// 위 초기 세 갈래 모두 { procedureCode, criticality, value }. 없으면 생성 코드가 어긋난 것
	const asn_TYPE_member_t *procedure_code_member = member_by_name(message_member->type, "procedureCode");
	const asn_TYPE_member_t *value_member = member_by_name(message_member->type, "value");
	if (!procedure_code_member || !value_member)
		return parse_fail(ngap_msg, NGAP_DECODE_FAILED);
	const NGAP_ProcedureCode_t *procedure_code = member_value_ptr(procedure_code_member, message);

	// value 는 절차 번호로 고르는 open type. 문법이 모르는 (절차, PDU 종류)면 asn1c 가 버려 고른 갈래가 없음
	const void *body = NULL;
	const asn_TYPE_member_t *body_member = choice_selected(value_member->type, member_value_ptr(value_member, message), &body, NULL);
	if (!body_member || !body)
		return parse_fail(ngap_msg, NGAP_UNKNOWN_MESSAGE);

	ngap_msg->procedure_code = *procedure_code;
	ngap_msg->pdu_type = pdu_type;
	ngap_msg->msg_name = body_member->type->name;
	// 이번 디코드에서 asn1c 가 버린 open type 수 = 문법이 모르는 IE 수(중첩 IE 포함). 본체를 버린 경우는 위에서 이미 실패로 끝남
	ngap_msg->unknown_ie_count = (int)(asn_portran_opentype_skipped_count - skipped_count_before);

	const asn_TYPE_member_t *ie_list_member = member_by_name(body_member->type, "protocolIEs");
	const void *ie_list = NULL;
	if (ie_list_member)
		ie_list = member_value_ptr(ie_list_member, body);
	if (!ie_list)
		// PrivateMessage: IE 목록이 protocolIEs 가 아닌 privateIEs. 꺼낼 IE 없음
		return NGAP_OK;

	int ie_count = _A_CSEQUENCE_FROM_VOID(ie_list)->count;
	for (int i = 0; i < ie_count; i++) {
		struct ie_view ie;
		if (!ie_at(ie_list_member->type, ie_list, i, &ie) || !ie.type)
			// 값이 없는 IE = asn1c 가 버린 IE. unknown_ie_count 에 이미 포함
			continue;
		enum ngap_result result = ie_take(ngap_msg, internal, &ie);
		if (result != NGAP_OK)
			return parse_fail(ngap_msg, result);
	}
	return NGAP_OK;
}
