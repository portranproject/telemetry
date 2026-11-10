/**
 * ngap.c
 * : NGAP PDU 한 개 디코드 -> 지표에 쓰는 값만 struct ngap_msg 로 전달 (TS 38.413 V15.8.0, APER, asn1c)
 *
 * [1] 흐름
 *
 *   ngap_parse(pdu_bytes, len, ngap_msg)        libsctp 가 재조립한 PPID 60 메시지 한 개
 *     |         인자 NULL, len 0             -> NGAP_DECODE_FAILED
 *     |         내부 상태 할당 실패          -> NGAP_NO_MEMORY
 *     |
 *     +---- 1. aper_decode_complete             asn1c 트리 생성 (힙, ngap_internal 소유)
 *     |         디코드 실패, 남는 바이트     -> NGAP_DECODE_FAILED
 *     |         문법이 모르는 IE             -> 버림 + unknown_ie_count
 *     |
 *     +---- 2. PDU 종류, 절차 번호, 본체     -> pdu_type, procedure_code, msg_name
 *     |         문법에 없는 (절차, PDU 종류) -> NGAP_UNKNOWN_MESSAGE
 *     |
 *     +---- 3. IE 목록: ie_at -> ie_take
 *               담는 24종 아님               -> 건너뜀
 *               같은 IE 재등장               -> 건너뜀 + duplicate_ie_count
 *               값 타입이 표와 다름          -> 건너뜀 + type_mismatch_ie_count
 *               값이 규격 범위 밖            -> 담지 않음 + rejected_ie_count
 *               그 외                        -> ngap_msg 필드
 *               배열 할당 실패               -> NGAP_NO_MEMORY
 *
 *   ngap_internal 을 잡은 뒤의 실패 반환은 전부 parse_fail 경유: 잡은 것 해제 + ngap_msg 를 값 없는 상태로
 *   ngap_release(ngap_msg)                      트리, 배열 해제. ngap_msg 의 해당 포인터는 NULL
 *
 * [2] 담는 범위
 *
 *   절차 53개(메시지 79종) -> 이름 79종 전부. 메시지별 코드 없이 asn1c 설명표에서 얻음
 *   IE 174개(최상위 137종) -> 아래 24종만. 지표와 탐지가 읽는 값
 *
 *   UE 식별
 *     RAN-UE-NGAP-ID (85)     ran_ue_ngap_id
 *     AMF-UE-NGAP-ID (10)     amf_ue_ngap_id
 *     UE-NGAP-IDs (114)       amf_ue_ngap_id, ran_ue_ngap_id
 *     NewAMF-UE-NGAP-ID (40)  new_amf_ue_ngap_id
 *     5G-S-TMSI (26)          stmsi48
 *
 *   F1과 대응
 *     NAS-PDU (38)                             nas_ies
 *     PDUSessionResourceSetupListCxtReq (71)   nas_ies, from_pdu_session_item = true
 *     PDUSessionResourceSetupListSUReq (74)    위와 같음
 *     PDUSessionResourceModifyListModReq (64)  위와 같음
 *     RRCEstablishmentCause (90)               rrc_establishment_cause
 *     UserLocationInformation (121)            uli_nr_cgi
 *
 *   연결 수명
 *     Cause (15)      cause
 *     ResetType (88)  reset_type, reset_ues
 *
 *   AMF 상태
 *     AMFOverloadResponse (2)                overload_response_present, overload_action_mask
 *     AMFTrafficLoadReductionIndication (9)  traffic_load_reduction_percent
 *     OverloadStartNSSAIList (49)            overload_nssai_list_present
 *     AMFName (1)                            amf_name, amf_name_len
 *     ServedGUAMIList (96)                   guami_digest
 *     UERetentionInformation (147)           ue_contexts_retained
 *     AMF-TNLAssociationToAddList (6)        tnla_add_ipv4
 *     AMF-TNLAssociationToRemoveList (7)     tnla_remove_ipv4
 *
 *   RRC INACTIVE 판정
 *     RRCState (92)                                     rrc_state
 *     CoreNetworkAssistanceInformationForInactive (18)  core_network_assistance_present
 *     RRCInactiveTransitionReportRequest (91)           inactive_report_requested
 *
 *   담지 않는 것
 *     SecurityKey (94), SecurityContext (93) 의 NH, MaskedIMEISV (34)
 *       비밀값과 영구 단말 식별자. 지표에 불필요 -> ngap_msg 에 필드 자체가 없음
 *     핸드오버 투명 컨테이너 (101, 106) 안의 RRCContainer, UERadioCapability (117)
 *       UE 로 가는 RRC 는 F1 의 RRC-Container 로 관측. 능력 정보는 지표에 불필요
 *     HandoverRequest 의 NASC (37)
 *       NAS 메시지가 아님 (TS 38.413 §9.2.3.4) -> libnas 대상 아님
 *
 *   NAS 내용은 바이트만 nas_ies 로 전달. 해석은 libnas 에서 진행
 */

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

// AMF-UE-NGAP-ID ::= INTEGER (0..1099511627775) (TS 38.413 §9.3.3.1). 40비트.
#define AMF_UE_NGAP_ID_MAX ((1ull << 40) - 1)

// TrafficLoadReductionIndication ::= INTEGER (1..99) (TS 38.413 §9.3.1.106). 필드 폭 7비트 -> 디코더는 128 까지 통과시킴
#define TRAFFIC_LOAD_REDUCTION_PERCENT_MIN 1
#define TRAFFIC_LOAD_REDUCTION_PERCENT_MAX 99

// FiveG-S-TMSI 의 세 필드: AMFSetID BIT STRING (SIZE(10)), AMFPointer BIT STRING (SIZE(6)), FiveG-TMSI OCTET STRING (SIZE(4)) (TS 38.413 §9.3.3.20)
#define AMF_SET_ID_BITS  10
#define AMF_POINTER_BITS 6
#define FIVEG_TMSI_BYTES 4

// TransportLayerAddress 가 IP 주소일 때의 폭. TS 38.413 §9.3.2.4 가 TS 38.414 로 넘김
//   TS 38.414 §5.3  a) 32 IPv4(RFC 791)  b) 128 IPv6(RFC 8200)  c) 160 둘 다 — 앞 32비트가 IPv4
#define IPV4_ADDRESS_BITS      32
#define IPV6_ADDRESS_BITS      128
#define IPV4_IPV6_ADDRESS_BITS 160

// 결과 배열(NAS, TNL 주소, RESET UE)의 첫 칸 수
#define ARRAY_FIRST_CAPACITY 4

// guami_digest_take 의 해시 상수. 식과 prime 은 FNV-1a(Fowler-Noll-Vo) 64비트
//   SEED 는 표준 시작값 14695981039346656037 에서 끝자리 7 이 빠진 값. 같은지만 비교하므로 영향 없음 -> 기존 출력 유지
#define GUAMI_DIGEST_SEED 1469598103934665603ull
#define FNV1A64_PRIME 1099511628211ull

// NRCellIdentity ::= BIT STRING (SIZE(36)) (TS 38.413 §9.3.1.7)
#define NR_CELL_IDENTITY_BITS 36

// asn1c 가 모르는 open type 을 버릴 때마다 +1
// TODO: libap 밖 의존. 정의는 asn1/asn1_glue.c (libasn1skel.a 에 링크) 확인 가능
extern unsigned long asn_portran_opentype_skipped_count;


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
	int tnla_add_capacity;
	uint32_t *tnla_remove_ipv4;
	int tnla_remove_capacity;
	struct ngap_reset_ue *reset_ues;
	int reset_ue_capacity;
	// 이 PDU 에서 이미 본 IE. 비트 n = TAKEN_IES[n]. 중복 판정용
	uint32_t seen_ie_mask;
};

// ie_view: IE 하나의 번호, 값.
struct ie_view {
	// IE 번호(ProtocolIE-ID)
	long id;
	// 값의 asn1c 타입. asn1c 가 값을 버린 IE(모르는 IE, 그 메시지에 없는 IE)면 NULL
	const asn_TYPE_descriptor_t *type;
	// 값 위치. type 이 NULL 이면 NULL
	const void *value;
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

// ie_at: IE 목록의 index 번째 IE. 범위 밖, 빈 칸이면 false
//
//   IE 한 개
//   +----+-------------+-------+
//   | id | criticality | value |     value = IE 번호로 고르는 open type. asn1c 는 CHOICE 로 생성
//   +----+-------------+-------+
//
//   asn1c 가 값을 버린 IE 면 true 에 ie->type, ie->value 가 NULL
static bool ie_at(const asn_TYPE_descriptor_t *list_type, const void *list, int index, struct ie_view *ie) {
	const asn_anonymous_sequence_ *ie_list = _A_CSEQUENCE_FROM_VOID(list);
	if (index < 0 || index >= ie_list->count || list_type->elements_count < 1)
		return false;
	const void *field = ie_list->array[index];
	const asn_TYPE_descriptor_t *field_type = list_type->elements[0].type;
	const asn_TYPE_member_t *id_member = member_by_name(field_type, "id");
	const asn_TYPE_member_t *value_member = member_by_name(field_type, "value");
	if (!field || !id_member || !value_member)
		return false;
	const NGAP_ProtocolIE_ID_t *id = member_value_ptr(id_member, field);
	const void *choice_base = member_value_ptr(value_member, field);
	if (!id || !choice_base)
		return false;

	const void *value = NULL;
	const asn_TYPE_member_t *value_choice = choice_selected(value_member->type, choice_base, &value, NULL);
	ie->id = *id;
	ie->type = NULL;
	ie->value = NULL;
	if (value_choice && value) {
		ie->type = value_choice->type;
		ie->value = value;
	}
	return true;
}

// ie_read_uint: 정수 IE 를 0 ~ max_value 로 읽음. 음수, 상한 초과, 정수 아님이면 false (*value_out 그대로). f1ap.c 와 같음
//   asn1c 는 범위가 32비트 안이면 long / unsigned long, 넘으면 부호 있는 바이트열(INTEGER_t)로 저장 -> asn_INTEGER2imax 로 읽고 음수 거부
//
//     AMF-UE-NGAP-ID 의 와이어 8옥텟   asn1c 저장       asn_INTEGER2umax      asn_INTEGER2imax
//     00 00 00 FF FF FF FF FF          2^40-1           2^40-1  담음          2^40-1  담음
//     00 00 01 00 00 00 00 00          2^40             2^40    거부          2^40    거부
//     FF FF FF FF FF FF FF FE          -2 (1옥텟 FE)    254     담음 (오류)   -2      거부
static bool ie_read_uint(const struct ie_view *ie, uint64_t max_value, uint64_t *value_out) {
	if (!ie->type || !ie->value)
		return false;
	if (ie->type->op == &asn_OP_INTEGER) {
		intmax_t big_value = 0;
		if (asn_INTEGER2imax(ie->value, &big_value) != 0)
			return false;
		if (big_value < 0 || (uint64_t)big_value > max_value)
			return false;
		*value_out = (uint64_t)big_value;
		return true;
	}
	if (ie->type->op != &asn_OP_NativeInteger)
		return false;
	const asn_INTEGER_specifics_t *specifics = ie->type->specifics;
	bool is_unsigned = specifics && specifics->field_unsigned;
	uint64_t uint_value = 0;
	if (is_unsigned) {
		uint_value = (uint64_t)*(const unsigned long *)ie->value;
	} else {
		long signed_value = *(const long *)ie->value;
		if (signed_value < 0)
			return false;
		uint_value = (uint64_t)signed_value;
	}
	if (uint_value > max_value)
		return false;
	*value_out = uint_value;
	return true;
}

// amf_ue_ngap_id_read: AMF-UE-NGAP-ID 를 읽음. IE 10, IE 40, IE 114 의 AMF 쪽, NG RESET 목록 항목이 공용
//   반환: 담았으면 true. 없으면(NULL) false. 범위 밖이면 false + rejected_ie_count
static bool amf_ue_ngap_id_read(struct ngap_msg *ngap_msg, const NGAP_AMF_UE_NGAP_ID_t *amf_ue_ngap_id, uint64_t *value_out) {
	if (!amf_ue_ngap_id)
		return false;
	const struct ie_view ie = {.type = &asn_DEF_NGAP_AMF_UE_NGAP_ID, .value = amf_ue_ngap_id};
	if (ie_read_uint(&ie, AMF_UE_NGAP_ID_MAX, value_out))
		return true;
	ngap_msg->rejected_ie_count++;
	return false;
}

// ran_ue_ngap_id_read: RAN-UE-NGAP-ID 를 읽음. IE 85, IE 114 의 RAN 쪽, NG RESET 목록 항목이 공용. 없으면(NULL) false
//   rejected_ie_count 없음: 와이어의 길이 필드가 4옥텟까지만 표현 -> 2^32-1 을 넘는 값이 올 수 없음
static bool ran_ue_ngap_id_read(const NGAP_RAN_UE_NGAP_ID_t *ran_ue_ngap_id, uint32_t *value_out) {
	const struct ie_view ie = {.type = &asn_DEF_NGAP_RAN_UE_NGAP_ID, .value = ran_ue_ngap_id};
	uint64_t uint_value = 0;
	if (!ie_read_uint(&ie, UINT32_MAX, &uint_value))
		return false;
	*value_out = (uint32_t)uint_value;
	return true;
}

// bits_read: BIT STRING(64비트 이하) -> 정수. 첫 비트가 최상위. 바이트 수, 미사용 비트 수가 bit_count 와 맞을 때만 true
//
//   AMF Set ID 10비트: 2바이트, 끝 6비트 미사용
//   buf   [ b0 ][ b1: 위 2비트만 유효 ]      value = (b0 b1) >> 6
static bool bits_read(const BIT_STRING_t *bits, unsigned bit_count, uint64_t *value_out) {
	size_t byte_count = (bit_count + 7) / 8;
	int unused_bits = (int)(byte_count * 8 - bit_count);
	if (!bits->buf || bits->size != byte_count || bits->bits_unused != unused_bits)
		return false;
	uint64_t uint_value = 0;
	for (size_t i = 0; i < byte_count; i++)
		uint_value = (uint_value << 8) | bits->buf[i];
	*value_out = uint_value >> unused_bits;
	return true;
}

// enum_read: 확장 가능한 열거형 값을 그대로 돌려줌. 이 문법이 모르는 확장값이면 -1 (asn1c 패치 04) + rejected_ie_count
//   쓰는 자리: 값이 -1 이면 결과가 'IE 없음' 과 같아지는 다섯 곳 (IE 90, 92, 91, 147, ResetAll)
//   Cause, Overload Action 은 is_present, overload_response_present 가 따로 있어 세지 않음
static long enum_read(struct ngap_msg *ngap_msg, long enum_value) {
	if (enum_value < 0)
		ngap_msg->rejected_ie_count++;
	return enum_value;
}

// nr_cgi_take: NR-CGI -> nr_cgi. 길이가 맞을 때만 유효, 아니면 전부 0.
static struct nr_cgi nr_cgi_take(const NGAP_NR_CGI_t *ngap_nr_cgi) {
	struct nr_cgi nr_cgi = {.is_valid = false};
	const OCTET_STRING_t *plmn = &ngap_nr_cgi->pLMNIdentity;
	uint64_t nr_cell_identity = 0;
	// PLMNIdentity ::= OCTET STRING (SIZE(3))
	bool is_plmn_valid = plmn->buf && plmn->size == sizeof(nr_cgi.plmn_identity);
	if (!is_plmn_valid || !bits_read(&ngap_nr_cgi->nRCellIdentity, NR_CELL_IDENTITY_BITS, &nr_cell_identity))
		return nr_cgi;
	memcpy(nr_cgi.plmn_identity, plmn->buf, sizeof(nr_cgi.plmn_identity));
	nr_cgi.nr_cell_identity = nr_cell_identity;
	nr_cgi.is_valid = true;
	return nr_cgi;
}

// cause_take: Cause(CHOICE) -> ap_cause (TS 38.413 §9.3.1.2).
//
//   group   0 radioNetwork   1 transport   2 nas   3 protocol   4 misc   5 choice-Extensions
//   value   범주 안의 순번. 이 문법이 모르는 확장값이면 -1, 이름 NULL (asn1c 패치 04. 0 으로 읽히는 것을 방지)
//
//   이름은 asn1c 생성 코드의 고정 문자열 -> ngap_release 뒤에도 유효
static struct ap_cause cause_take(const NGAP_Cause_t *ngap_cause) {
	struct ap_cause cause = {.group = -1, .value = -1};
	const void *selected = NULL;
	unsigned present = 0;
	const asn_TYPE_member_t *group_member = choice_selected(&asn_DEF_NGAP_Cause, ngap_cause, &selected, &present);
	if (!group_member)
		return cause;
	cause.is_present = true;
	cause.group = (int)present - 1;
	cause.group_name = group_member->name;
	bool is_enumerated = selected && group_member->type->op == &asn_OP_NativeEnumerated;
	if (!is_enumerated)
		return cause;
	const asn_INTEGER_enum_map_t *value_entry = INTEGER_map_value2enum(group_member->type->specifics, *(const long *)selected);
	if (!value_entry)
		return cause;
	cause.value = (int)value_entry->nat_value;
	cause.value_name = value_entry->enum_name;
	return cause;
}

// ue_ngap_ids_take: UE-NGAP-IDs(IE 114, UE CONTEXT RELEASE COMMAND)의 AMF 쪽, RAN 쪽 ID
//   AMF ID 단독, 또는 짝(AMF ID + RAN ID). 짝의 AMF ID 가 범위 밖이어도 RAN ID 는 담음
//   IE 10, IE 85 와 같은 메시지에 실리지 않음 (15.8.0 에서 IE 114 는 이 메시지에만) -> 앞 값을 덮을 일 없음
static void ue_ngap_ids_take(struct ngap_msg *ngap_msg, const NGAP_UE_NGAP_IDs_t *ue_ngap_ids) {
	switch (ue_ngap_ids->present) {
	case NGAP_UE_NGAP_IDs_PR_aMF_UE_NGAP_ID:
		ngap_msg->has_amf_ue_ngap_id = amf_ue_ngap_id_read(ngap_msg, &ue_ngap_ids->choice.aMF_UE_NGAP_ID, &ngap_msg->amf_ue_ngap_id);
		break;
	case NGAP_UE_NGAP_IDs_PR_uE_NGAP_ID_pair: {
		const NGAP_UE_NGAP_ID_pair_t *id_pair = ue_ngap_ids->choice.uE_NGAP_ID_pair;
		if (!id_pair)
			break;
		ngap_msg->has_amf_ue_ngap_id = amf_ue_ngap_id_read(ngap_msg, &id_pair->aMF_UE_NGAP_ID, &ngap_msg->amf_ue_ngap_id);
		ngap_msg->has_ran_ue_ngap_id = ran_ue_ngap_id_read(&id_pair->rAN_UE_NGAP_ID, &ngap_msg->ran_ue_ngap_id);
		break;
	}
	default:
		break;
	}
}

// stmsi48_take: 5G-S-TMSI(IE 26)의 세 필드를 48비트 하나로 이음 (TS 23.003 §2.10.1)
//
//   47            38 37         32 31                             0
//   +---------------+-------------+--------------------------------+
//   | AMF Set ID 10 | AMF Ptr 6   | 5G-TMSI 32                     |
//   +---------------+-------------+--------------------------------+
//
//   RRC 의 ng-5G-S-TMSI(BIT STRING 48)와 같은 값 -> F1 쪽 레코드와 그대로 비교 가능
//   세 필드의 크기는 문법에 고정. 어긋나 있으면 담지 않음 + rejected_ie_count
static void stmsi48_take(struct ngap_msg *ngap_msg, const NGAP_FiveG_S_TMSI_t *fiveg_s_tmsi) {
	const OCTET_STRING_t *fiveg_tmsi_octets = &fiveg_s_tmsi->fiveG_TMSI;
	uint64_t amf_set_id = 0;
	uint64_t amf_pointer = 0;
	bool is_valid = bits_read(&fiveg_s_tmsi->aMFSetID, AMF_SET_ID_BITS, &amf_set_id)
		&& bits_read(&fiveg_s_tmsi->aMFPointer, AMF_POINTER_BITS, &amf_pointer)
		&& fiveg_tmsi_octets->buf
		&& fiveg_tmsi_octets->size == FIVEG_TMSI_BYTES;
	if (!is_valid) {
		ngap_msg->rejected_ie_count++;
		return;
	}
	uint64_t fiveg_tmsi = 0;
	for (size_t i = 0; i < FIVEG_TMSI_BYTES; i++)
		fiveg_tmsi = (fiveg_tmsi << 8) | fiveg_tmsi_octets->buf[i];
	ngap_msg->stmsi48 = (amf_set_id << 38) | (amf_pointer << 32) | fiveg_tmsi;
	ngap_msg->has_stmsi48 = true;
}

// overload_response_take: AMF Overload Response(IE 2)의 조치를 비트 하나로. 조치 순번 n -> 1 << n
//   overload_response_present = IE 가 있었음. 모르는 확장 조치면 마스크 0
static void overload_response_take(struct ngap_msg *ngap_msg, const NGAP_OverloadResponse_t *overload_response) {
	ngap_msg->overload_response_present = true;
	if (overload_response->present != NGAP_OverloadResponse_PR_overloadAction)
		return;
	long overload_action = overload_response->choice.overloadAction;
	if (overload_action >= 0 && overload_action < 32)
		ngap_msg->overload_action_mask = 1u << overload_action;
}

// amf_name_take: AMF Name(IE 1). 길이는 amf_name_len (asn1c 가 끝에 NUL 을 붙이나 약속 아님)
//   APER 디코더는 PrintableString 의 알파벳, 크기 미검사 -> asn1c 가 생성한 제약 함수로 검사 (TS 38.413 §9.3.3.21)
//   실패 -> 담지 않음 + rejected_ie_count. 151옥텟 이상도 거부 (와이어로는 적법, 제약 함수는 1..150 만 수용)
static void amf_name_take(struct ngap_msg *ngap_msg, const OCTET_STRING_t *octets) {
	if (!octets->buf || NGAP_AMFName_constraint(&asn_DEF_NGAP_AMFName, octets, NULL, NULL) != 0) {
		ngap_msg->rejected_ie_count++;
		return;
	}
	ngap_msg->amf_name = (const char *)octets->buf;
	ngap_msg->amf_name_len = octets->size;
}

// fnv_bytes: hash 에 바이트열을 섞음. 바이트마다 xor 후 prime 곱
static uint64_t fnv_bytes(uint64_t hash, const uint8_t *bytes, size_t byte_count) {
	for (size_t i = 0; i < byte_count; i++) {
		hash ^= bytes[i];
		hash *= FNV1A64_PRIME;
	}
	return hash;
}

// fnv_bits: hash 에 BIT STRING 을 섞음. 바이트열 뒤에 미사용 비트 수도 섞어 길이가 다른 비트열을 구별
static uint64_t fnv_bits(uint64_t hash, const BIT_STRING_t *bits) {
	if (!bits->buf)
		return hash;
	hash = fnv_bytes(hash, bits->buf, bits->size);
	uint8_t unused_bits = (uint8_t)bits->bits_unused;
	return fnv_bytes(hash, &unused_bits, 1);
}

// guami_digest_take: Served GUAMI List(IE 96) -> 64비트 요약값. 쓰임이 '같은 AMF 인가' 비교뿐이라 목록은 미보관
//   항목마다 아래 바이트를 차례로 해시에 넣음
//
//     PLMN            3옥텟
//     AMF Region ID   1옥텟 + bits_unused(0)
//     AMF Set ID      2옥텟 + bits_unused(6)
//     AMF Pointer     1옥텟 + bits_unused(2)
//     0x7C            항목 경계
//
//   항목 순서가 바뀌면 값도 바뀜
static void guami_digest_take(struct ngap_msg *ngap_msg, const NGAP_ServedGUAMIList_t *guami_list) {
	uint64_t guami_digest = GUAMI_DIGEST_SEED;
	const uint8_t item_boundary = 0x7C;
	for (int i = 0; i < guami_list->list.count; i++) {
		const NGAP_ServedGUAMIItem_t *guami_item = guami_list->list.array[i];
		if (!guami_item)
			continue;
		const NGAP_GUAMI_t *guami = &guami_item->gUAMI;
		if (guami->pLMNIdentity.buf)
			guami_digest = fnv_bytes(guami_digest, guami->pLMNIdentity.buf, guami->pLMNIdentity.size);
		guami_digest = fnv_bits(guami_digest, &guami->aMFRegionID);
		guami_digest = fnv_bits(guami_digest, &guami->aMFSetID);
		guami_digest = fnv_bits(guami_digest, &guami->aMFPointer);
		guami_digest = fnv_bytes(guami_digest, &item_boundary, 1);
	}
	ngap_msg->guami_digest = guami_digest;
	ngap_msg->has_guami_digest = true;
}

// array_grow: 결과 배열을 늘림. 처음이면 ARRAY_FIRST_CAPACITY 칸, 아니면 2배. 실패하면 NULL(array, *capacity 그대로).
//   개수가 칸 수에 닿았을 때 호출. realloc 으로 자리가 옮겨질 수 있어 호출한 쪽이 포인터를 다시 가리킴
static void *array_grow(void *array, int *capacity, size_t element_bytes) {
	if (*capacity > INT_MAX / 2)
		return NULL;
	int new_capacity = *capacity == 0 ? ARRAY_FIRST_CAPACITY : *capacity * 2;
	void *grown = realloc(array, (size_t)new_capacity * element_bytes);
	if (!grown)
		return NULL;
	*capacity = new_capacity;
	return grown;
}

// nas_push: NAS-PDU 하나를 nas_ies 끝에 추가. 메모리 부족이면 false
//   바이트는 복사하지 않고 asn1c 트리 안을 가리킴
//   길이를 가리지 않고 그대로 넘김. 길이 0 도 한 칸 (개수, 순서 유지). 형식 판정은 libnas (3옥텟 미만은 NAS 메시지 아님, TS 24.501 §9.1.1)
//   librrc 의 dedicatedNAS-Message 와 같은 규칙
static bool nas_push(struct ngap_msg *ngap_msg, struct ngap_internal *internal, const OCTET_STRING_t *octets, bool from_pdu_session_item) {
	if (ngap_msg->nas_ie_count == internal->nas_ie_capacity) {
		struct ngap_nas *grown = array_grow(internal->nas_ies, &internal->nas_ie_capacity, sizeof(*grown));
		if (!grown)
			return false;
		internal->nas_ies = grown;
		ngap_msg->nas_ies = grown;
	}
	internal->nas_ies[ngap_msg->nas_ie_count] = (struct ngap_nas){
		.data = octets->size > 0 ? octets->buf : NULL,
		.len = octets->size,
		.from_pdu_session_item = from_pdu_session_item,
	};
	ngap_msg->nas_ie_count++;
	return true;
}

// item_nas_take: PDU 세션 목록(IE 71, 74, 64)의 항목마다 NAS-PDU 를 찾아 nas_ies 에 추가
//   NAS 멤버는 이름이 아닌 타입으로 고름. 이름이 메시지마다 다름 (nAS-PDU, pDUSessionNAS-PDU)
//   반환: NGAP_OK / NGAP_NO_MEMORY
static enum ngap_result item_nas_take(struct ngap_msg *ngap_msg, struct ngap_internal *internal, const struct ie_view *ie) {
	const asn_anonymous_sequence_ *item_list = _A_CSEQUENCE_FROM_VOID(ie->value);
	const asn_TYPE_descriptor_t *item_type = ie->type->elements[0].type;
	for (int i = 0; i < item_list->count; i++) {
		const void *item = item_list->array[i];
		if (!item)
			continue;
		for (unsigned member_index = 0; member_index < item_type->elements_count; member_index++) {
			const asn_TYPE_member_t *member = &item_type->elements[member_index];
			if (member->type != &asn_DEF_NGAP_NAS_PDU)
				continue;
			const OCTET_STRING_t *octets = member_value_ptr(member, item);
			if (octets && !nas_push(ngap_msg, internal, octets, true))
				return NGAP_NO_MEMORY;
		}
	}
	return NGAP_OK;
}

// tnla_take: TNL Association to Add(IE 6) / Remove(IE 7) List 의 IPv4 주소를 *ipv4_out 배열에 모음. 개수는 *count_out
//
//   항목의 주소 (CPTransportLayerInformation)
//     endpointIPAddress                              주소만
//     choice-Extensions: EndpointIPAddressAndPort    주소 + 포트 (IE 169). 주소만 담음
//
//   주소 = BIT STRING (SIZE(1..160, ...))
//     폭(비트)    뜻                처리
//     32          IPv4              담음. 비교 대상 cap_record.src_addr 가 IPv4
//     160         IPv4+IPv6         앞 32비트가 IPv4 라 그 4옥텟을 담음 (TS 38.414 §5.3 c)
//     128         IPv6 만           담지 않음. 배열이 uint32_t 라 담을 자리가 없음
//     그 외       IP 주소 아님      rejected_ie_count
//
//   폭 = size * 8 - bits_unused. size 만 보면 25비트 주소도 4옥텟이라 IPv4 로 읽힘
//   반환: NGAP_OK / NGAP_NO_MEMORY (그때까지 모은 배열은 *ipv4_out 에 남음. 해제는 ngap_release)
static enum ngap_result tnla_take(struct ngap_msg *ngap_msg, const struct ie_view *ie, uint32_t **ipv4_out, int *count_out, int *capacity_out) {
	const asn_anonymous_sequence_ *item_list = _A_CSEQUENCE_FROM_VOID(ie->value);
	const asn_TYPE_member_t *address_member = member_by_name(ie->type->elements[0].type, "aMF-TNLAssociationAddress");
	if (!address_member || address_member->type != &asn_DEF_NGAP_CPTransportLayerInformation)
		return NGAP_OK;
	for (int i = 0; i < item_list->count; i++) {
		const void *item = item_list->array[i];
		if (!item)
			continue;
		const NGAP_CPTransportLayerInformation_t *cp_transport_info = member_value_ptr(address_member, item);
		if (!cp_transport_info)
			continue;
		const BIT_STRING_t *address = NULL;
		if (cp_transport_info->present == NGAP_CPTransportLayerInformation_PR_endpointIPAddress) {
			address = &cp_transport_info->choice.endpointIPAddress;
		} else if (cp_transport_info->present == NGAP_CPTransportLayerInformation_PR_choice_Extensions && cp_transport_info->choice.choice_Extensions) {
			// asn1c 는 이 CHOICE 의 choice-Extensions 를 NGAP_CPTransportLayerInformation_ExtIEs 로 생성 (ProtocolIE-SingleContainer 의 typedef)
			const NGAP_CPTransportLayerInformation_ExtIEs_t *extension = (const void *)cp_transport_info->choice.choice_Extensions;
			if (extension->value.present == NGAP_CPTransportLayerInformation_ExtIEs__value_PR_EndpointIPAddressAndPort)
				address = &extension->value.choice.EndpointIPAddressAndPort.endpointIPAddress;
		}
		if (!address || !address->buf)
			continue;
		size_t address_bits = address->size * 8 - (size_t)address->bits_unused;
		if (address_bits == IPV6_ADDRESS_BITS)
			continue;
		if (address_bits != IPV4_ADDRESS_BITS && address_bits != IPV4_IPV6_ADDRESS_BITS) {
			ngap_msg->rejected_ie_count++;
			continue;
		}
		if (*count_out == *capacity_out) {
			uint32_t *grown = array_grow(*ipv4_out, capacity_out, sizeof(*grown));
			if (!grown)
				return NGAP_NO_MEMORY;
			*ipv4_out = grown;
		}
		// 앞 4옥텟을 와이어 바이트 순서 그대로 (= cap_record.src_addr). 160비트면 그 뒤 128비트가 IPv6
		memcpy(&(*ipv4_out)[*count_out], address->buf, sizeof(uint32_t));
		(*count_out)++;
	}
	return NGAP_OK;
}

// reset_take: ResetType(IE 88, NG RESET) -> reset_type, reset_ues. f1ap.c reset_take 와 같은 규칙
//
//   nG-Interface          reset-all 일 때만 RESET_TYPE_ALL. 모르는 확장값이면 RESET_TYPE_NONE (범위 모름) + rejected_ie_count
//   partOfNG-Interface    RESET_TYPE_PART + 목록의 항목을 메시지 안 순서대로 reset_ues 에
//
//   항목의 AMF ID, RAN ID 는 둘 다 OPTIONAL (TS 38.413 §9.3.3.25). 둘 다 없는 항목도 그대로 담음 (§8.7.4.2.1, §8.7.4.2.2 의 빈 항목)
//   AMF ID 가 범위 밖이면 rejected_ie_count, 그 항목은 has_amf_ue_ngap_id = false
//   반환: NGAP_OK / NGAP_NO_MEMORY
static enum ngap_result reset_take(struct ngap_msg *ngap_msg, struct ngap_internal *internal, const NGAP_ResetType_t *ngap_reset_type) {
	if (ngap_reset_type->present == NGAP_ResetType_PR_nG_Interface) {
		if (enum_read(ngap_msg, ngap_reset_type->choice.nG_Interface) == NGAP_ResetAll_reset_all)
			ngap_msg->reset_type = RESET_TYPE_ALL;
		return NGAP_OK;
	}
	if (ngap_reset_type->present != NGAP_ResetType_PR_partOfNG_Interface)
		return NGAP_OK;
	ngap_msg->reset_type = RESET_TYPE_PART;
	const NGAP_UE_associatedLogicalNG_connectionList_t *connection_list = ngap_reset_type->choice.partOfNG_Interface;
	if (!connection_list)
		return NGAP_OK;

	for (int i = 0; i < connection_list->list.count; i++) {
		const NGAP_UE_associatedLogicalNG_connectionItem_t *connection = connection_list->list.array[i];
		if (!connection)
			continue;
		if (ngap_msg->reset_ue_count == internal->reset_ue_capacity) {
			struct ngap_reset_ue *grown = array_grow(internal->reset_ues, &internal->reset_ue_capacity, sizeof(*grown));
			if (!grown)
				return NGAP_NO_MEMORY;
			internal->reset_ues = grown;
			ngap_msg->reset_ues = grown;
		}
		struct ngap_reset_ue reset_ue = {.has_amf_ue_ngap_id = false};
		reset_ue.has_amf_ue_ngap_id = amf_ue_ngap_id_read(ngap_msg, connection->aMF_UE_NGAP_ID, &reset_ue.amf_ue_ngap_id);
		reset_ue.has_ran_ue_ngap_id = ran_ue_ngap_id_read(connection->rAN_UE_NGAP_ID, &reset_ue.ran_ue_ngap_id);
		internal->reset_ues[ngap_msg->reset_ue_count] = reset_ue;
		ngap_msg->reset_ue_count++;
	}
	return NGAP_OK;
}

// TAKEN_IES: 담는 IE 표. IE 번호 -> 값 타입 (머리 주석 [2] 의 표와 같은 순서)
static const struct taken_ie {
	long id;
	const asn_TYPE_descriptor_t *type;
} TAKEN_IES[] = {
	{ NGAP_ProtocolIE_ID_id_RAN_UE_NGAP_ID,    &asn_DEF_NGAP_RAN_UE_NGAP_ID },
	{ NGAP_ProtocolIE_ID_id_AMF_UE_NGAP_ID,    &asn_DEF_NGAP_AMF_UE_NGAP_ID },
	{ NGAP_ProtocolIE_ID_id_UE_NGAP_IDs,       &asn_DEF_NGAP_UE_NGAP_IDs },
	{ NGAP_ProtocolIE_ID_id_NewAMF_UE_NGAP_ID, &asn_DEF_NGAP_AMF_UE_NGAP_ID },
	{ NGAP_ProtocolIE_ID_id_FiveG_S_TMSI,      &asn_DEF_NGAP_FiveG_S_TMSI },
	{ NGAP_ProtocolIE_ID_id_NAS_PDU,                           &asn_DEF_NGAP_NAS_PDU },
	{ NGAP_ProtocolIE_ID_id_PDUSessionResourceSetupListCxtReq, &asn_DEF_NGAP_PDUSessionResourceSetupListCxtReq },
	{ NGAP_ProtocolIE_ID_id_PDUSessionResourceSetupListSUReq,  &asn_DEF_NGAP_PDUSessionResourceSetupListSUReq },
	{ NGAP_ProtocolIE_ID_id_PDUSessionResourceModifyListModReq, &asn_DEF_NGAP_PDUSessionResourceModifyListModReq },
	{ NGAP_ProtocolIE_ID_id_RRCEstablishmentCause,   &asn_DEF_NGAP_RRCEstablishmentCause },
	{ NGAP_ProtocolIE_ID_id_UserLocationInformation, &asn_DEF_NGAP_UserLocationInformation },
	{ NGAP_ProtocolIE_ID_id_Cause,     &asn_DEF_NGAP_Cause },
	{ NGAP_ProtocolIE_ID_id_ResetType, &asn_DEF_NGAP_ResetType },
	{ NGAP_ProtocolIE_ID_id_AMFOverloadResponse,               &asn_DEF_NGAP_OverloadResponse },
	{ NGAP_ProtocolIE_ID_id_AMFTrafficLoadReductionIndication, &asn_DEF_NGAP_TrafficLoadReductionIndication },
	{ NGAP_ProtocolIE_ID_id_OverloadStartNSSAIList,            &asn_DEF_NGAP_OverloadStartNSSAIList },
	{ NGAP_ProtocolIE_ID_id_AMFName,                           &asn_DEF_NGAP_AMFName },
	{ NGAP_ProtocolIE_ID_id_ServedGUAMIList,                   &asn_DEF_NGAP_ServedGUAMIList },
	{ NGAP_ProtocolIE_ID_id_UERetentionInformation,            &asn_DEF_NGAP_UERetentionInformation },
	{ NGAP_ProtocolIE_ID_id_AMF_TNLAssociationToAddList,       &asn_DEF_NGAP_AMF_TNLAssociationToAddList },
	{ NGAP_ProtocolIE_ID_id_AMF_TNLAssociationToRemoveList,    &asn_DEF_NGAP_AMF_TNLAssociationToRemoveList },
	{ NGAP_ProtocolIE_ID_id_RRCState,                                    &asn_DEF_NGAP_RRCState },
	{ NGAP_ProtocolIE_ID_id_CoreNetworkAssistanceInformationForInactive, &asn_DEF_NGAP_CoreNetworkAssistanceInformationForInactive },
	{ NGAP_ProtocolIE_ID_id_RRCInactiveTransitionReportRequest,          &asn_DEF_NGAP_RRCInactiveTransitionReportRequest },
};

#define TAKEN_IE_COUNT ((int)(sizeof(TAKEN_IES) / sizeof(TAKEN_IES[0])))
_Static_assert(TAKEN_IE_COUNT <= 32, "seen_ie_mask 는 32비트");

// ie_take: 최상위 IE 하나를 ngap_msg 에 담음
//
//   TAKEN_IES 에 없는 번호   -> 건너뜀
//   이미 본 번호             -> 건너뜀 + duplicate_ie_count. 첫 것만 담음
//                               규격상 초과 출현은 추상 구문 오류, 받는 쪽은 절차 거부 (TS 38.413 §10.3.6). 관측자는 거부 불가 -> 첫 값 + 계수
//   값 타입이 표와 다름      -> 건너뜀 + type_mismatch_ie_count. 15.8.0 에서 IE 번호마다 값 타입은 하나 -> 문법이 바뀐 경우만 해당
//
//   반환: NGAP_OK / NGAP_NO_MEMORY (결과 배열을 늘리지 못함)
static enum ngap_result ie_take(struct ngap_msg *ngap_msg, struct ngap_internal *internal, const struct ie_view *ie) {
	int taken_index = 0;
	while (taken_index < TAKEN_IE_COUNT && TAKEN_IES[taken_index].id != ie->id)
		taken_index++;
	if (taken_index == TAKEN_IE_COUNT)
		return NGAP_OK;
	if (internal->seen_ie_mask & (1u << taken_index)) {
		ngap_msg->duplicate_ie_count++;
		return NGAP_OK;
	}
	/* 타입을 마스크보다 먼저 봄. 거꾸로 두면 타입이 틀린 IE 가 그 칸을 '봤음' 으로 점유해, 뒤에 온
	   올바른 IE 가 duplicate_ie_count 로 둔갑함 — 타입 혼동 입력과 중복 송신이 같은 모양이 됨.

	   도달 가능성: 15.8.0 문법에서는 도달하지 않음. ie->type 은 asn1c 가 IE 번호로 고른 CHOICE
	   가지이고, 이 문법은 최상위 IE 컨테이너가 쓰는 IE 번호 150개 전부가 값 타입 하나씩임
	   ((ID, TYPE) 항목 395개를 전수로 재서 번호 하나에 타입 둘인 경우 0개). 그래도 분기와 계수기를
	   두는 이유: 상대가 우리보다 새 판이어서 어떤 번호의 타입이 바뀌면 그때 조용히 틀리기 때문임.
	   수동 관측자는 다시 달라고 할 수 없어, 못 읽은 것을 '없었다' 로 처리하면 지표가 조용히 거짓이 됨. */
	if (ie->type != TAKEN_IES[taken_index].type) {
		ngap_msg->type_mismatch_ie_count++;
		return NGAP_OK;
	}
	internal->seen_ie_mask |= 1u << taken_index;

	switch (ie->id) {
	// [UE 식별]
	case NGAP_ProtocolIE_ID_id_RAN_UE_NGAP_ID:
		ngap_msg->has_ran_ue_ngap_id = ran_ue_ngap_id_read(ie->value, &ngap_msg->ran_ue_ngap_id);
		break;
	case NGAP_ProtocolIE_ID_id_AMF_UE_NGAP_ID:
		ngap_msg->has_amf_ue_ngap_id = amf_ue_ngap_id_read(ngap_msg, ie->value, &ngap_msg->amf_ue_ngap_id);
		break;
	case NGAP_ProtocolIE_ID_id_UE_NGAP_IDs:
		ue_ngap_ids_take(ngap_msg, ie->value);
		break;
	// UE CONTEXT MODIFICATION REQUEST: 이 UE 의 AMF 쪽 ID 변경 (TS 38.413 §8.3.4.2)
	case NGAP_ProtocolIE_ID_id_NewAMF_UE_NGAP_ID:
		ngap_msg->has_new_amf_ue_ngap_id = amf_ue_ngap_id_read(ngap_msg, ie->value, &ngap_msg->new_amf_ue_ngap_id);
		break;
	case NGAP_ProtocolIE_ID_id_FiveG_S_TMSI:
		stmsi48_take(ngap_msg, ie->value);
		break;
	case NGAP_ProtocolIE_ID_id_NAS_PDU:
		if (!nas_push(ngap_msg, internal, ie->value, false))
			return NGAP_NO_MEMORY;
		break;
	case NGAP_ProtocolIE_ID_id_PDUSessionResourceSetupListCxtReq:
	case NGAP_ProtocolIE_ID_id_PDUSessionResourceSetupListSUReq:
	case NGAP_ProtocolIE_ID_id_PDUSessionResourceModifyListModReq:
		return item_nas_take(ngap_msg, internal, ie);
	// 모르는 확장값(mo-ExceptionData 등)이면 -1
	case NGAP_ProtocolIE_ID_id_RRCEstablishmentCause:
		ngap_msg->rrc_establishment_cause = (int)enum_read(ngap_msg, *(const NGAP_RRCEstablishmentCause_t *)ie->value);
		break;
	// NR 위치일 때만. E-UTRA, N3IWF 면 is_valid = false 유지
	case NGAP_ProtocolIE_ID_id_UserLocationInformation: {
		const NGAP_UserLocationInformation_t *user_location = ie->value;
		if (user_location->present == NGAP_UserLocationInformation_PR_userLocationInformationNR && user_location->choice.userLocationInformationNR)
			ngap_msg->uli_nr_cgi = nr_cgi_take(&user_location->choice.userLocationInformationNR->nR_CGI);
		break;
	}

	// [연결 수명]
	case NGAP_ProtocolIE_ID_id_Cause:
		ngap_msg->cause = cause_take(ie->value);
		break;
	case NGAP_ProtocolIE_ID_id_ResetType:
		return reset_take(ngap_msg, internal, ie->value);

	// [AMF 상태]
	case NGAP_ProtocolIE_ID_id_AMFOverloadResponse:
		overload_response_take(ngap_msg, ie->value);
		break;
	case NGAP_ProtocolIE_ID_id_AMFTrafficLoadReductionIndication: {
		uint64_t traffic_load_reduction_percent = 0;
		bool is_in_range = ie_read_uint(ie, TRAFFIC_LOAD_REDUCTION_PERCENT_MAX, &traffic_load_reduction_percent)
			&& traffic_load_reduction_percent >= TRAFFIC_LOAD_REDUCTION_PERCENT_MIN;
		if (is_in_range)
			ngap_msg->traffic_load_reduction_percent = (int)traffic_load_reduction_percent;
		else
			ngap_msg->rejected_ie_count++;
		break;
	}
	case NGAP_ProtocolIE_ID_id_OverloadStartNSSAIList:
		ngap_msg->overload_nssai_list_present = true;
		break;
	case NGAP_ProtocolIE_ID_id_AMFName:
		amf_name_take(ngap_msg, ie->value);
		break;
	case NGAP_ProtocolIE_ID_id_ServedGUAMIList:
		guami_digest_take(ngap_msg, ie->value);
		break;
	case NGAP_ProtocolIE_ID_id_UERetentionInformation:
		ngap_msg->ue_contexts_retained = enum_read(ngap_msg, *(const NGAP_UERetentionInformation_t *)ie->value) == NGAP_UERetentionInformation_ues_retained;
		break;
	case NGAP_ProtocolIE_ID_id_AMF_TNLAssociationToAddList: {
		enum ngap_result result = tnla_take(ngap_msg, ie, &internal->tnla_add_ipv4, &ngap_msg->tnla_add_count, &internal->tnla_add_capacity);
		ngap_msg->tnla_add_ipv4 = internal->tnla_add_ipv4;
		return result;
	}
	case NGAP_ProtocolIE_ID_id_AMF_TNLAssociationToRemoveList: {
		enum ngap_result result = tnla_take(ngap_msg, ie, &internal->tnla_remove_ipv4, &ngap_msg->tnla_remove_count, &internal->tnla_remove_capacity);
		ngap_msg->tnla_remove_ipv4 = internal->tnla_remove_ipv4;
		return result;
	}

	// [RRC INACTIVE 판정]
	case NGAP_ProtocolIE_ID_id_RRCState:
		ngap_msg->rrc_state = (int)enum_read(ngap_msg, *(const NGAP_RRCState_t *)ie->value);
		break;
	case NGAP_ProtocolIE_ID_id_CoreNetworkAssistanceInformationForInactive:
		ngap_msg->core_network_assistance_present = true;
		break;
	// 보고를 요청하는 두 값일 때만 true. cancel-report 와 모르는 확장값은 요청 아님
	case NGAP_ProtocolIE_ID_id_RRCInactiveTransitionReportRequest: {
		long report_request = enum_read(ngap_msg, *(const NGAP_RRCInactiveTransitionReportRequest_t *)ie->value);
		ngap_msg->inactive_report_requested = report_request == NGAP_RRCInactiveTransitionReportRequest_subsequent_state_transition_report
			|| report_request == NGAP_RRCInactiveTransitionReportRequest_single_rrc_connected_state_report;
		break;
	}
	}
	return NGAP_OK;
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
