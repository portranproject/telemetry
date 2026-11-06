#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <F1AP_F1AP-PDU.h>
#include <F1AP_NRCGI.h>
#include <F1AP_ProcedureCode.h>
#include <F1AP_ProtocolIE-ID.h>
#include <NativeInteger.h>
#include <OCTET_STRING.h>
#include <asn_SEQUENCE_OF.h>
#include <constr_CHOICE.h>

#include "ap.h"

// MARK: - 상수

// asn1c 디코드 재귀 스택 상한. 깊게 중첩한 입력으로 스택이 넘치지 않게(넘으면 디코드 실패)
#define DECODE_MAX_STACK_BYTES (256 * 1024)

// NRCellIdentity ::= BIT STRING (SIZE(36)) (TS 38.473). asn1c 는 앞에서부터 채운 5바이트와 끝 미사용 4비트로 담음
#define NR_CELL_IDENTITY_BITS 36
#define NR_CELL_IDENTITY_BYTES ((NR_CELL_IDENTITY_BITS + 7) / 8)
#define NR_CELL_IDENTITY_UNUSED_BITS (NR_CELL_IDENTITY_BYTES * 8 - NR_CELL_IDENTITY_BITS)

// SRBID ::= INTEGER (0..3, ..., 4 | 5) (TS 38.473). 이보다 크면 모르는 SRB 라 없음
#define SRB_ID_MAX 5

// RRC 컨테이너 배열을 처음 잡을 때 칸 수. 한 메시지에 보통 1~2개(INITIAL UL RRC 가 2개)라 늘리는 일이 거의 없게
#define RRC_CONTAINER_FIRST_CAPACITY 4

// MARK: - 자료구조

// f1ap_internal: f1ap_msg.internal 이 가리키는 f1ap.c 전용 상태. f1ap_release 가 해제
//   f1ap_parse 가 0 으로 채워 할당. SRB ID·배열 칸은 IE 를 꺼내는 코드가 채우고, 그 전에는 0·NULL
struct f1ap_internal {
    F1AP_F1AP_PDU_t *pdu; // asn1c 가 디코드한 트리. 꺼낸 바이트 포인터가 이 트리를 빌림
    bool has_srb_id;      // IE 를 도는 중에 SRB ID 를 봤는지
    int srb_id;           // 그 값. SRB ID IE 가 RRC 컨테이너보다 뒤에 올 수 있어, IE 를 다 돈 뒤 컨테이너마다 붙임

    // 결과 배열. f1ap_msg 쪽은 const 라, 늘리고 풀 때는 이쪽을 씀(캐스트 없이)
    struct f1ap_rrc_container *rrc_containers; // f1ap_msg.rrc_containers 와 같은 배열
    int rrc_container_capacity;                // rrc_containers 에 할당한 칸 수. 개수가 닿으면 늘림
    struct nr_cgi *served_cells;               // f1ap_msg.served_cells 와 같은 배열
    int served_cell_capacity;                  // served_cells 에 할당한 칸 수. 개수가 닿으면 늘림
};

// ie_view: IE 하나의 번호·값. 메시지마다 다른 C 타입 대신 이 모양으로 읽음(값은 트리를 가리킴)
struct ie_view {
    long id;                           // IE 번호(ProtocolIE-ID). 꺼낼 값을 고르는 기준
    const asn_TYPE_descriptor_t *type; // 값의 asn1c 타입. 읽기 전에 타입을 보려고 둠. asn1c 가 값을 건너뛴 IE(모르는 IE, 그 메시지에 없는 IE)면 NULL
    const void *value;                 // 값 위치. type 이 NULL 이면 NULL
};

// MARK: - asn1c 설명표 읽기

/* member_by_name: 설명표(type)에서 이름이 name 인 멤버를 찾음. 없으면 NULL.
 *   이유: 메시지마다 다른 C 타입 대신 문법의 이름("procedureCode" 등)으로 찾아, 모든 메시지를 같은 코드로 읽음
 */
static const asn_TYPE_member_t *member_by_name(const asn_TYPE_descriptor_t *type, const char *name) {
    for (unsigned i = 0; i < type->elements_count; i++) {
        const char *member_name = type->elements[i].name;
        if (member_name && strcmp(member_name, name) == 0)
            return &type->elements[i];
    }
    return NULL;
}

/* member_value_ptr: 구조체 안 멤버 값의 위치. 포인터로 담는 멤버(ATF_POINTER)는 따라감(비면 NULL) */
static const void *member_value_ptr(const asn_TYPE_member_t *member, const void *struct_base) {
    const void *value_ptr = (const char *)struct_base + member->memb_offset;
    if (member->flags & ATF_POINTER)
        value_ptr = *(const void *const *)value_ptr;
    return value_ptr;
}

/* choice_selected: CHOICE 에서 고른 갈래와 값 위치. present_out 에 고른 순번(1부터, 0 = 없음).
 *   PDU 갈래·메시지 본체·IE 값에 같이 씀. 고른 것이 없으면(모르는 open type) NULL 이고 *value_out 도 NULL
 */
static const asn_TYPE_member_t *choice_selected(const asn_TYPE_descriptor_t *type, const void *choice_base, const void **value_out,
                                                unsigned *present_out) {
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

/* ie_at: IE 목록의 index 번째 IE 를 설명표의 "id"·"value" 로 읽음. 범위 밖·빈 칸이면 false.
 *   이유: IE 목록의 C 타입이 메시지마다 달라, 설명표로 읽어야 한 코드로 고를 수 있음.
 *   asn1c 가 값을 건너뛴 IE(모르는 IE, 그 메시지에 없는 IE)면 true 에 ie->type·value NULL. ie 는 트리를 빌림
 */
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
    const F1AP_ProtocolIE_ID_t *id = member_value_ptr(id_member, field);
    const void *choice_base = member_value_ptr(value_member, field);
    if (!id || !choice_base)
        return false;

    // value 는 IE 번호로 고르는 open type. 문법이 모르는 번호면 asn1c 가 건너뛰어 고른 갈래가 없음
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

// MARK: - IE 값 꺼내기

/* ie_read_uint: 정수 IE 를 0 ~ max_value 로 읽음. 음수·상한 초과·정수 아님이면 false(*value_out 그대로).
 *   이유: 확장 값을 칸에 잘라 담으면 없는 번호가 됨(예 -5 → 4294967291)
 */
static bool ie_read_uint(const struct ie_view *ie, uint64_t max_value, uint64_t *value_out) {
    if (!ie->type || !ie->value || ie->type->op != &asn_OP_NativeInteger)
        return false;
    // long·unsigned long 중 무엇으로 담았는지는 field_unsigned 가 알림
    const asn_INTEGER_specifics_t *specifics = ie->type->specifics;
    bool is_unsigned = specifics && specifics->field_unsigned;
    uint64_t value = 0;
    if (is_unsigned) {
        value = (uint64_t)*(const unsigned long *)ie->value;
    } else {
        long signed_value = *(const long *)ie->value;
        if (signed_value < 0)
            return false;
        value = (uint64_t)signed_value;
    }
    if (value > max_value)
        return false;
    *value_out = value;
    return true;
}

/* nr_cgi_take: NRCGI → nr_cgi. 셀 번호는 5바이트를 이어 붙여 미사용 4비트만큼 오른쪽으로. 길이가 맞을 때만 유효, 아니면 전부 0.
 *   이유: asn1c 판이 바뀌어 담는 모양이 달라져도 버퍼 밖을 읽지 않게 길이부터 봄
 */
static struct nr_cgi nr_cgi_take(const F1AP_NRCGI_t *f1ap_nr_cgi) {
    struct nr_cgi nr_cgi = {.is_valid = false};
    const OCTET_STRING_t *plmn = &f1ap_nr_cgi->pLMN_Identity;
    const BIT_STRING_t *cell = &f1ap_nr_cgi->nRCellIdentity;
    bool is_plmn_valid = plmn->buf && plmn->size == sizeof(nr_cgi.plmn_identity); // PLMN-Identity ::= OCTET STRING (SIZE(3))
    bool is_cell_valid = cell->buf
                      && cell->size == NR_CELL_IDENTITY_BYTES
                      && cell->bits_unused == NR_CELL_IDENTITY_UNUSED_BITS;
    if (!is_plmn_valid || !is_cell_valid)
        return nr_cgi;

    memcpy(nr_cgi.plmn_identity, plmn->buf, sizeof(nr_cgi.plmn_identity));
    uint64_t cell_bits = 0;
    for (size_t i = 0; i < NR_CELL_IDENTITY_BYTES; i++)
        cell_bits = (cell_bits << 8) | cell->buf[i];
    nr_cgi.nr_cell_identity = cell_bits >> NR_CELL_IDENTITY_UNUSED_BITS;
    nr_cgi.is_valid = true;
    return nr_cgi;
}

/* rrc_container_push: RRC 컨테이너 하나를 결과 배열 끝에 더함. 칸이 차면 2배로 늘림. 메모리 부족이면 false.
 *   이유: 컨테이너 수는 메시지마다 달라 미리 정할 수 없음(같은 IE 가 여러 번 와도 모두 담음).
 *   data 는 트리의 바이트를 빌림(복사 안 함). srb_id 는 -1 로 두고 IE 를 다 돈 뒤 f1ap_parse 가 붙임
 */
static bool rrc_container_push(struct f1ap_msg *f1ap_msg, struct f1ap_internal *internal, int ie_id, const OCTET_STRING_t *octets) {
    if (f1ap_msg->rrc_container_count == internal->rrc_container_capacity) {
        if (internal->rrc_container_capacity > INT_MAX / 2)
            return false; // 2배가 int 를 넘음. 입력 길이로는 닿지 않는 수
        int new_capacity = internal->rrc_container_capacity == 0 ? RRC_CONTAINER_FIRST_CAPACITY : internal->rrc_container_capacity * 2;
        struct f1ap_rrc_container *grown = realloc(internal->rrc_containers, (size_t)new_capacity * sizeof(*grown));
        if (!grown)
            return false;
        internal->rrc_containers = grown;
        internal->rrc_container_capacity = new_capacity;
        f1ap_msg->rrc_containers = grown; // realloc 으로 자리가 옮겨질 수 있어 늘릴 때마다 다시 가리킴
    }
    internal->rrc_containers[f1ap_msg->rrc_container_count] = (struct f1ap_rrc_container){
        .ie_id = ie_id,
        .srb_id = -1,
        .data = octets->buf,
        .len = octets->size,
    };
    f1ap_msg->rrc_container_count++;
    return true;
}

/* take_ie: 최상위 IE 하나를 번호로 골라 f1ap_msg 에 채움(SRB ID 는 internal). 꺼내지 않는 번호·값 없는 IE 는 지나감.
 *   이유: 같은 값이 CU 구현마다 다른 메시지에 실려(OCUDU·OAI) 번호로 고름.
 *   정수는 범위 밖이면 없음, NR CGI 는 타입이 NRCGI 일 때만. 같은 번호가 두 번 오면 뒤의 것(정수는 읽을 수 있는 값만).
 *   RRC 컨테이너는 같은 번호가 여러 번 와도 모두 담음.
 *   반환: F1AP_OK / F1AP_NO_MEMORY(컨테이너 배열을 늘리지 못함)
 */
static enum f1ap_result take_ie(struct f1ap_msg *f1ap_msg, struct f1ap_internal *internal, const struct ie_view *ie) {
    uint64_t value = 0;
    switch (ie->id) {
    case F1AP_ProtocolIE_ID_id_gNB_CU_UE_F1AP_ID:
        if (ie_read_uint(ie, UINT32_MAX, &value)) {
            f1ap_msg->cu_ue_id = (uint32_t)value;
            f1ap_msg->has_cu_ue_id = true;
        }
        break;
    case F1AP_ProtocolIE_ID_id_gNB_DU_UE_F1AP_ID:
        if (ie_read_uint(ie, UINT32_MAX, &value)) {
            f1ap_msg->du_ue_id = (uint32_t)value;
            f1ap_msg->has_du_ue_id = true;
        }
        break;
    case F1AP_ProtocolIE_ID_id_oldgNB_DU_UE_F1AP_ID:
        if (ie_read_uint(ie, UINT32_MAX, &value)) {
            f1ap_msg->old_du_ue_id = (uint32_t)value;
            f1ap_msg->has_old_du_ue_id = true;
        }
        break;
    case F1AP_ProtocolIE_ID_id_C_RNTI:
        if (ie_read_uint(ie, UINT32_MAX, &value)) {
            f1ap_msg->crnti = (uint32_t)value;
            f1ap_msg->has_crnti = true;
        }
        break;
    case F1AP_ProtocolIE_ID_id_SRBID:
        if (ie_read_uint(ie, SRB_ID_MAX, &value)) {
            internal->srb_id = (int)value;
            internal->has_srb_id = true;
        }
        break;
    case F1AP_ProtocolIE_ID_id_NRCGI:
        if (ie->type == &asn_DEF_F1AP_NRCGI)
            f1ap_msg->nr_cgi = nr_cgi_take(ie->value);
        break;
    case F1AP_ProtocolIE_ID_id_RRCContainer:
    case F1AP_ProtocolIE_ID_id_RRCContainer_RRCSetupComplete:
    case F1AP_ProtocolIE_ID_id_DUtoCURRCContainer:
        if (!ie->type || ie->type->op != &asn_OP_OCTET_STRING)
            break; // 바이트 열(OCTET STRING)이 아니면 담는 모양을 모름
        if (!rrc_container_push(f1ap_msg, internal, (int)ie->id, ie->value))
            return F1AP_NO_MEMORY;
        if (ie->id == F1AP_ProtocolIE_ID_id_DUtoCURRCContainer)
            f1ap_msg->has_du_to_cu_rrc_container = true;
        break;
    default:
        break; // 꺼내지 않는 IE
    }
    return F1AP_OK;
}

// MARK: - 해석

/* msg_clear: f1ap_msg 를 꺼낸 값이 없는 상태로 만듦. 0 이 올바른 값인 칸(cause 범주·값)은 -1 */
static void msg_clear(struct f1ap_msg *f1ap_msg) {
    memset(f1ap_msg, 0, sizeof(*f1ap_msg));
    f1ap_msg->cause.group = -1;
    f1ap_msg->cause.value = -1;
}

/* f1ap_release: 트리 → 결과 배열 → 내부 상태 순으로 풀고, f1ap_msg 의 포인터를 NULL·0 으로. 약속은 ap.h */
void f1ap_release(struct f1ap_msg *f1ap_msg) {
    if (!f1ap_msg || !f1ap_msg->internal)
        return;
    struct f1ap_internal *internal = f1ap_msg->internal;
    ASN_STRUCT_FREE(asn_DEF_F1AP_F1AP_PDU, internal->pdu); // pdu 가 NULL 이어도 됨(asn1c 가 확인)
    free(internal->rrc_containers);
    free(internal->served_cells);
    free(internal);
    f1ap_msg->internal = NULL;
    f1ap_msg->rrc_container_count = 0;
    f1ap_msg->rrc_containers = NULL;
    f1ap_msg->served_cell_count = 0;
    f1ap_msg->served_cells = NULL;
}

/* parse_fail: 해석 실패 처리. 잡은 것을 모두 해제하고 f1ap_msg 를 값 없는 상태로 되돌림.
 *   이유: 실패하면 해제할 것이 없고 꺼낸 값도 남지 않는다는 ap.h 의 약속을 실패하는 곳마다 같은 방법으로 지킴.
 *   반환: result 그대로
 */
static enum f1ap_result parse_fail(struct f1ap_msg *f1ap_msg, enum f1ap_result result) {
    f1ap_release(f1ap_msg);
    msg_clear(f1ap_msg);
    return result;
}

/* f1ap_parse: 입력 검사 → APER 디코드 → 꼬리 검사 → PDU 종류 → 절차 번호·메시지 이름 → IE 를 번호로 골라 채움 → RRC 컨테이너에 SRB ID.
 *   내부 상태를 잡은 뒤의 실패는 모두 parse_fail 로 끝냄. 약속(소유권·반환·실패 상태)은 ap.h
 */
enum f1ap_result f1ap_parse(const uint8_t *pdu_bytes, size_t len, struct f1ap_msg *f1ap_msg) {
    if (!f1ap_msg)
        return F1AP_DECODE_FAILED;
    msg_clear(f1ap_msg);
    if (!pdu_bytes || len == 0)
        return F1AP_DECODE_FAILED;

    struct f1ap_internal *internal = calloc(1, sizeof(*internal));
    if (!internal)
        return F1AP_NO_MEMORY;
    f1ap_msg->internal = internal;

    const asn_codec_ctx_t decode_ctx = {.max_stack_size = DECODE_MAX_STACK_BYTES};
    asn_dec_rval_t decoded = aper_decode_complete(&decode_ctx, &asn_DEF_F1AP_F1AP_PDU, (void **)&internal->pdu, pdu_bytes, len);
    // APER PDU 는 바이트 단위로 끝나므로 정상 PDU 는 len 바이트를 정확히 다 씀. 남으면 의미 없는 바이트가 붙은 것
    bool is_whole_pdu = decoded.code == RC_OK && decoded.consumed == len;
    if (!is_whole_pdu)
        return parse_fail(f1ap_msg, F1AP_DECODE_FAILED);

    // PDU 의 세 갈래(initiatingMessage / successfulOutcome / unsuccessfulOutcome). 그 밖(choice-extension)은 다룰 것이 없음
    const void *outcome = NULL;
    unsigned pdu_present = 0;
    const asn_TYPE_member_t *outcome_member = choice_selected(&asn_DEF_F1AP_F1AP_PDU, internal->pdu, &outcome, &pdu_present);
    if (!outcome_member || !outcome)
        return parse_fail(f1ap_msg, F1AP_UNKNOWN_MESSAGE);
    enum f1ap_pdu_type pdu_type;
    switch (pdu_present) {
    case F1AP_F1AP_PDU_PR_initiatingMessage:
        pdu_type = F1AP_PDU_INITIATING;
        break;
    case F1AP_F1AP_PDU_PR_successfulOutcome:
        pdu_type = F1AP_PDU_SUCCESSFUL;
        break;
    case F1AP_F1AP_PDU_PR_unsuccessfulOutcome:
        pdu_type = F1AP_PDU_UNSUCCESSFUL;
        break;
    default:
        return parse_fail(f1ap_msg, F1AP_UNKNOWN_MESSAGE);
    }

    // 세 갈래 모두 { procedureCode, criticality, value }. 없으면 생성 코드가 어긋난 것
    const asn_TYPE_member_t *procedure_code_member = member_by_name(outcome_member->type, "procedureCode");
    const asn_TYPE_member_t *value_member = member_by_name(outcome_member->type, "value");
    if (!procedure_code_member || !value_member)
        return parse_fail(f1ap_msg, F1AP_DECODE_FAILED);
    const F1AP_ProcedureCode_t *procedure_code = member_value_ptr(procedure_code_member, outcome);

    // value 는 절차 번호로 고르는 open type. 문법이 모르는 절차면 asn1c 가 건너뛰어 고른 갈래가 없음
    const void *body = NULL;
    const asn_TYPE_member_t *body_member = choice_selected(value_member->type, member_value_ptr(value_member, outcome), &body, NULL);
    if (!body_member || !body)
        return parse_fail(f1ap_msg, F1AP_UNKNOWN_MESSAGE);

    f1ap_msg->procedure_code = *procedure_code;
    f1ap_msg->pdu_type = pdu_type;
    f1ap_msg->msg_name = body_member->type->name;

    // 본체의 IE 목록을 하나씩 보며 번호로 골라 채움
    const asn_TYPE_member_t *ie_list_member = member_by_name(body_member->type, "protocolIEs");
    const void *ie_list = NULL;
    if (ie_list_member)
        ie_list = member_value_ptr(ie_list_member, body);
    if (!ie_list)
        return F1AP_OK; // PrivateMessage 처럼 IE 목록이 protocolIEs 가 아닌 본체. 꺼낼 IE 가 없음

    int ie_count = _A_CSEQUENCE_FROM_VOID(ie_list)->count;
    for (int i = 0; i < ie_count; i++) {
        struct ie_view ie;
        if (!ie_at(ie_list_member->type, ie_list, i, &ie))
            continue;
        enum f1ap_result result = take_ie(f1ap_msg, internal, &ie);
        if (result != F1AP_OK)
            return parse_fail(f1ap_msg, result);
    }

    // SRB ID IE 가 컨테이너보다 뒤에 올 수 있어 IE 를 다 돈 뒤 붙임. DU to CU 컨테이너는 RRC 메시지가 아니라 붙이지 않음
    for (int i = 0; i < f1ap_msg->rrc_container_count; i++) {
        bool is_rrc_message = internal->rrc_containers[i].ie_id != F1AP_ProtocolIE_ID_id_DUtoCURRCContainer;
        if (internal->has_srb_id && is_rrc_message)
            internal->rrc_containers[i].srb_id = internal->srb_id;
    }
    return F1AP_OK;
}
