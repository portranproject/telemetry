#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <F1AP_F1AP-PDU.h>
#include <F1AP_ProcedureCode.h>
#include <constr_CHOICE.h>

#include "ap.h"

// MARK: - 상수

// asn1c 디코드의 재귀 스택 상한(256 KiB). 일부러 깊게 중첩한 입력이 스택을 넘치게 하지 못하도록. 넘으면 디코드 실패
#define DECODE_MAX_STACK_BYTES (256 * 1024)

// MARK: - 자료구조

// f1ap_internal: f1ap_msg.internal 이 가리키는 f1ap.c 전용 상태. f1ap_release 가 해제
//   f1ap_parse 가 0 으로 채워 할당. SRB ID·배열 칸은 IE 를 꺼내는 코드가 채우고, 그 전에는 0·NULL
struct f1ap_internal {
    F1AP_F1AP_PDU_t *pdu; // asn1c 가 디코드한 트리. 꺼낸 바이트 포인터가 이 트리를 빌림
    bool has_srb_id;      // IE 를 도는 중에 SRB ID(IE 64)를 봤는지
    int srb_id;           // 그 값. SRB ID IE 가 RRC 컨테이너보다 뒤에 올 수 있어, IE 를 다 돈 뒤 컨테이너마다 붙임

    // 결과 배열. f1ap_msg 쪽 포인터는 위 층이 읽기만 하도록 const 라, 늘리고 풀 때는 이쪽 포인터를 씀(const 를 벗기는 캐스트 없이)
    struct f1ap_rrc_container *rrc_containers; // f1ap_msg.rrc_containers 와 같은 배열
    int rrc_container_capacity;                // rrc_containers 에 할당한 칸 수. 개수가 닿으면 늘림
    struct nr_cgi *served_cells;               // f1ap_msg.served_cells 와 같은 배열
    int served_cell_capacity;                  // served_cells 에 할당한 칸 수. 개수가 닿으면 늘림
};

// MARK: - asn1c 설명표 읽기

/* member_by_name: asn1c 타입 설명표(type)의 멤버 중 이름이 name 인 것을 찾음.
 *   이유: 메시지 종류와 상관없이 같은 코드로 읽으려면 메시지마다 다른 C 타입 대신 설명표의 멤버 이름
 *   ("procedureCode", "value" 등, 문법의 ASN.1 이름)으로 찾아가야 함.
 *   반환: 멤버. 없으면 NULL. 설명표는 생성 코드의 고정 데이터라 프로그램 끝까지 유효
 */
static const asn_TYPE_member_t *member_by_name(const asn_TYPE_descriptor_t *type, const char *name) {
    for (unsigned i = 0; i < type->elements_count; i++) {
        const char *member_name = type->elements[i].name;
        if (member_name && strcmp(member_name, name) == 0)
            return &type->elements[i];
    }
    return NULL;
}

/* member_value_ptr: 구조체(struct_base) 안 멤버(member) 값의 위치.
 *   멤버를 포인터로 담는 경우(asn1c 의 ATF_POINTER — 선택 멤버, CHOICE 의 큰 갈래)는 그 포인터가 가리키는 곳.
 *   반환: 값 위치. 포인터로 담는 멤버가 비어 있으면 NULL
 */
static const void *member_value_ptr(const asn_TYPE_member_t *member, const void *struct_base) {
    const void *value_ptr = (const char *)struct_base + member->memb_offset;
    if (member->flags & ATF_POINTER)
        value_ptr = *(const void *const *)value_ptr;
    return value_ptr;
}

/* choice_selected: CHOICE 값(choice_base)에서 고른 갈래와 그 값의 위치를 찾음.
 *   이유: F1AP-PDU 의 세 갈래, 메시지 본체(value), IE 의 값이 모두 CHOICE 라 같은 방법으로 고른 쪽을 읽음.
 *   present_out 이 NULL 이 아니면 고른 순번(1부터, 0 = 고른 것 없음)을 씀.
 *   반환: 고른 갈래. 고른 것이 없거나(문법이 모르는 open type 은 asn1c 가 건너뛰어 0) 순번이 범위 밖이면 NULL 이고 *value_out 도 NULL
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

// MARK: - 해석

/* msg_clear: f1ap_msg 를 꺼낸 값이 없는 상태로 만듦. 0 이 올바른 값인 칸(cause 범주·값)은 -1 */
static void msg_clear(struct f1ap_msg *f1ap_msg) {
    memset(f1ap_msg, 0, sizeof(*f1ap_msg));
    f1ap_msg->cause.group = -1;
    f1ap_msg->cause.value = -1;
}

/* f1ap_release: f1ap_parse 가 잡은 asn1c 트리, 결과 배열, 내부 상태를 해제.
 *   돌아온 뒤 rrc_containers·served_cells 와 그 안의 바이트 포인터는 무효(NULL·0 으로 바꿈).
 *   msg_name·cause 이름은 생성 코드의 고정 문자열이라 그대로 유효.
 *   f1ap_msg 가 NULL 이거나 해제할 것이 없으면 아무것도 하지 않음. 두 번 불러도 됨.
 */
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

/* f1ap_parse: F1AP PDU 하나를 해석해 f1ap_msg 에 값을 채움.
 *   이유: Table I·II 와 탐지에 쓰는 값만 asn1c 타입 없이 넘겨, 위 층이 asn1c 를 몰라도 되게 함.
 *   순서: 입력 검사 → APER 디코드 → 꼬리 검사 → PDU 종류 → 절차 번호·메시지 이름.
 *   pdu_bytes 는 호출한 쪽 소유. 돌아온 뒤에는 쓰지 않음(필요한 바이트는 asn1c 트리에 복사됨).
 *   반환: F1AP_OK(뒤에 f1ap_release 로 해제) / F1AP_DECODE_FAILED / F1AP_UNKNOWN_MESSAGE / F1AP_NO_MEMORY.
 *   실패하면 f1ap_msg 는 값 없는 상태이고 해제할 것도 없음.
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

    // 세 갈래 모두 { procedureCode, criticality, value } 모양. 생성 코드의 멤버라 없으면 문법과 코드가 어긋난 것
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
    return F1AP_OK;
}
