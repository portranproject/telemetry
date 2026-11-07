#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <BIT_STRING.h>
#include <INTEGER.h>
#include <NR_CipheringAlgorithm.h>
#include <NR_DL-CCCH-Message.h>
#include <NR_DL-DCCH-Message.h>
#include <NR_EstablishmentCause.h>
#include <NR_IntegrityProtAlgorithm.h>
#include <NR_RRCReconfiguration-IEs.h>
#include <NR_RRCReject-IEs.h>
#include <NR_RRCSetupComplete-IEs.h>
#include <NR_RRCSetupRequest-IEs.h>
#include <NR_RadioBearerConfig.h>
#include <NR_SecurityConfig.h>
#include <NR_SecurityModeCommand-IEs.h>
#include <NR_UL-CCCH-Message.h>
#include <NR_UL-CCCH1-Message.h>
#include <NR_UL-DCCH-Message.h>
#include <constr_CHOICE.h>
#include <constr_SEQUENCE.h>
#include <uper_decoder.h>

#include "rrc.h"

// MARK: - 상수

// asn1c 디코드 재귀 스택 상한. 깊게 중첩한 입력으로 스택이 넘치지 않게(넘으면 디코드 실패). F1AP 와 같은 값
#define DECODE_MAX_STACK_BYTES (256 * 1024)

// SRB 의 PDCP 데이터 PDU 머리: R 4비트 + 일련번호 12비트 (TS 38.323 §6.2.2.1)
#define PDCP_HEADER_BYTES 2
// SRB 의 PDCP 데이터 PDU 꼬리 MAC-I. SRB 는 무결성이 꺼져 있어도 칸이 있음 (TS 38.323 §6.3.4)
#define PDCP_MAC_I_BYTES 4
// PDCP 모양의 최소 길이: 머리 + RRC 1바이트 이상 + MAC-I. 이보다 짧으면 RRC 가 들어 있을 수 없음
#define PDCP_MIN_BYTES (PDCP_HEADER_BYTES + 1 + PDCP_MAC_I_BYTES)

// 바이트 하나의 비트 수. UPER 는 마지막 바이트를 채움 비트로 채우므로 남은 비트가 이보다 적으면 채움뿐
#define BYTE_BITS 8

// 메시지까지 내려가는 CHOICE 겹 수 상한. 가장 깊은 곳은 UL-DCCH 의 MessageType → messageClassExtension → c2 (3겹)
#define MESSAGE_CHOICE_MAX_DEPTH 3
// 본문(…-IEs)까지 내려가는 CHOICE 겹 수 상한. criticalExtensions → c1 (2겹, 문법의 11곳)
#define BODY_CHOICE_MAX_DEPTH 2
// nonCriticalExtension 사슬을 따라가는 상한. 트리는 끝이 있어 닿지 않으며, 생성 코드가 어긋났을 때 멈추지 않는 일을 막는 안전장치
#define EXTENSION_CHAIN_MAX_LENGTH 32

// RRCSetupRequest ue-Identity(ng-5G-S-TMSI-Part1·randomValue) 비트 수 (문법 nr-rrc-17.3.0.asn1 1393–1394줄 SIZE (39))
#define UE_IDENTITY_BITS 39
// RRCSetupComplete ng-5G-S-TMSI 비트 수 (문법 6829줄 NG-5G-S-TMSI ::= BIT STRING (SIZE (48)))
#define S_TMSI_BITS 48
// RRCSetupComplete ng-5G-S-TMSI-Part2 비트 수: 5G-S-TMSI 의 왼쪽 9비트. 오른쪽 39비트는 RRCSetupRequest 의 Part1 (TS 38.331 §6.2.2, 문법 1349줄 SIZE (9))
#define S_TMSI_PART2_BITS 9
// RRCReject waitTime 범위(초): RejectWaitTime ::= INTEGER (1..16) (문법 9079줄). 디코더가 지키지만 uint8_t 로 옮기기 전에 다시 봄
#define REJECT_WAIT_TIME_MIN_S 1
#define REJECT_WAIT_TIME_MAX_S 16

// f1ap_procedure: RRC 컨테이너가 실리는 F1AP 절차 번호 (문법 f1ap-18.8.0.asn 17767–17775줄)
//   이 7개만 둠. f1ap_msg.procedure_code 는 long 그대로 두고 이 값들과 비교만 함
enum f1ap_procedure {
    F1AP_PROCEDURE_UE_CONTEXT_SETUP = 5,
    F1AP_PROCEDURE_UE_CONTEXT_RELEASE = 6,
    F1AP_PROCEDURE_UE_CONTEXT_MODIFICATION = 7,
    F1AP_PROCEDURE_UE_CONTEXT_MODIFICATION_REQUIRED = 8, // 성공 응답이 UE CONTEXT MODIFICATION CONFIRM
    F1AP_PROCEDURE_INITIAL_UL_RRC_MESSAGE_TRANSFER = 11,
    F1AP_PROCEDURE_DL_RRC_MESSAGE_TRANSFER = 12,
    F1AP_PROCEDURE_UL_RRC_MESSAGE_TRANSFER = 13,
};

// SRB ID 0 = SRB0 = CCCH 를 쓰는 유일한 SRB
#define SRB_ID_CCCH 0
// DCCH 를 쓰는 SRB ID 의 끝: SRB1~5. F1AP 문법 SRBID ::= INTEGER (0..3, ..., 4 | 5)
#define SRB_ID_DCCH_MAX 5

// UL-CCCH1 메시지(RRCResumeRequest1) 바이트 수: CCCH1 은 64비트, CCCH 는 48비트
#define UL_CCCH1_MESSAGE_BYTES 8

// MARK: - 자료구조

// rrc_internal: rrc_msg.internal 이 가리키는 rrc.c 전용 상태. rrc_release 가 해제
struct rrc_internal {
    const asn_TYPE_descriptor_t *message_type; // 트리를 푼 최상위 타입(채널마다 다름). 해제할 때 같은 타입으로 풀어야 함
    void *message;                             // asn1c 가 디코드한 트리. NAS·조각 포인터가 이 트리를 빌림
};

// body_result: 메시지에서 본문을 찾은 결과
enum body_result {
    BODY_FOUND,  // 값이 든 본문(…-IEs)
    BODY_FUTURE, // criticalExtensionsFuture 나 그 안 spare. 우리 문법으로는 뜻을 알 수 없음
};

// extension_slot: 본문 끝의 빈 nonCriticalExtension 자리(새 릴리스가 새 필드를 붙이는 곳)의 상태
enum extension_slot {
    EXTENSION_SLOT_NONE,    // 사슬이 없음(크기 고정 메시지 등). 남는 비트를 설명할 수 없음
    EXTENSION_SLOT_ABSENT,  // 사슬 중간이나 끝 자리가 "없음"으로 표시됨
    EXTENSION_SLOT_PRESENT, // 끝 빈 자리까지 "있음". 뒤에 새 릴리스 필드가 붙을 수 있음
};

// MARK: - asn1c 설명표 읽기

/* member_by_name: 설명표(type)에서 이름이 name 인 멤버를 찾음. 없으면 NULL.
 *   이유: 메시지마다 다른 C 타입 대신 문법의 이름("criticalExtensions" 등)으로 찾아, 모든 메시지를 같은 코드로 읽음
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

/* choice_selected: CHOICE 에서 고른 갈래와 값 위치. 고른 것이 없으면 NULL 이고 *value_out 도 NULL */
static const asn_TYPE_member_t *choice_selected(const asn_TYPE_descriptor_t *type, const void *choice_base, const void **value_out) {
    unsigned present = CHOICE_variant_get_presence(type, choice_base);
    *value_out = NULL;
    if (present == 0 || present > type->elements_count)
        return NULL;
    const asn_TYPE_member_t *member = &type->elements[present - 1];
    *value_out = member_value_ptr(member, choice_base);
    return member;
}

/* choice_descend: CHOICE 를 고른 갈래대로 max_depth 겹까지 따라 내려감. *type·*value 를 닿은 곳으로 바꿈.
 *   고른 갈래가 없으면 false. CHOICE 가 아닌 곳에 닿으면 멈추고 true(그곳이 무엇인지는 부르는 쪽이 봄)
 */
static bool choice_descend(const asn_TYPE_descriptor_t **type, const void **value, int max_depth) {
    for (int depth = 0; depth < max_depth && (*type)->op == &asn_OP_CHOICE; depth++) {
        const void *selected_value = NULL;
        const asn_TYPE_member_t *selected = choice_selected(*type, *value, &selected_value);
        if (!selected || !selected_value)
            return false;
        *type = selected->type;
        *value = selected_value;
    }
    return true;
}

/* is_empty_sequence: 멤버가 없는 SEQUENCE {} 인지. 문법의 확장 자리(messageClassExtension, …Future, 끝 nonCriticalExtension)가 이 모양.
 *   메시지와 본문(…-IEs)은 멤버가 하나 이상이라(문법 조사 2026-11-07: 빈 …-IEs 0곳) 이것으로 가름
 */
static bool is_empty_sequence(const asn_TYPE_descriptor_t *type) {
    return type->op == &asn_OP_SEQUENCE && type->elements_count == 0;
}

// MARK: - 메시지·본문·확장 자리 찾기

/* channel_message_type: 채널의 문법 최상위 타입(…-Message). 모르는 채널이면 NULL */
static const asn_TYPE_descriptor_t *channel_message_type(enum rrc_channel channel) {
    switch (channel) {
    case RRC_CHANNEL_UL_CCCH:
        return &asn_DEF_NR_UL_CCCH_Message;
    case RRC_CHANNEL_UL_CCCH1:
        return &asn_DEF_NR_UL_CCCH1_Message;
    case RRC_CHANNEL_UL_DCCH:
        return &asn_DEF_NR_UL_DCCH_Message;
    case RRC_CHANNEL_DL_CCCH:
        return &asn_DEF_NR_DL_CCCH_Message;
    case RRC_CHANNEL_DL_DCCH:
        return &asn_DEF_NR_DL_DCCH_Message;
    case RRC_CHANNEL_NONE:
        break;
    }
    return NULL;
}

/* message_find: 최상위 …-Message = { message MessageType } 에서 고른 메시지 하나를 찾음.
 *   MessageType 은 CHOICE { c1 CHOICE {…}, messageClassExtension … }. UL-DCCH 만 messageClassExtension 이 CHOICE { c2 CHOICE {…}, …Future }.
 *   고른 갈래를 끝까지 따라가 내용 있는 SEQUENCE 에 닿으면 메시지. spare(NULL)·빈 SEQUENCE(확장 자리)면 메시지가 아님.
 *   반환: 메시지 설명표(이름은 ->name, ASN.1 타입 이름). 값 위치는 *value_out. 메시지가 아니면 NULL
 */
static const asn_TYPE_descriptor_t *message_find(const asn_TYPE_descriptor_t *message_type, const void *tree, const void **value_out) {
    *value_out = NULL;
    const asn_TYPE_member_t *message_member = member_by_name(message_type, "message");
    if (!message_member)
        return NULL;
    const asn_TYPE_descriptor_t *type = message_member->type;
    const void *value = member_value_ptr(message_member, tree);
    if (!value || !choice_descend(&type, &value, MESSAGE_CHOICE_MAX_DEPTH))
        return NULL;
    bool is_message = type->op == &asn_OP_SEQUENCE && !is_empty_sequence(type);
    if (!is_message)
        return NULL;
    *value_out = value;
    return type;
}

/* body_find: 메시지에서 값이 든 본문(…-IEs)을 찾음. *body_type_out·*body_out 에 본문.
 *   criticalExtensions 가 있으면 CHOICE 를 따라감(그 안에 c1 이 한 겹 더 있는 메시지 포함). 빈 SEQUENCE(criticalExtensionsFuture)·spare 면 BODY_FUTURE.
 *   criticalExtensions 가 없는 메시지(RRCSetupRequest 등 = SEQUENCE { …-IEs } 하나)는 그 멤버가 본문. 그 밖의 모양이면 메시지 자체를 본문으로 봄
 */
static enum body_result body_find(const asn_TYPE_descriptor_t *message_type, const void *message, const asn_TYPE_descriptor_t **body_type_out,
                                  const void **body_out) {
    *body_type_out = message_type;
    *body_out = message;
    const asn_TYPE_member_t *extensions_member = member_by_name(message_type, "criticalExtensions");
    if (!extensions_member) {
        bool is_single_body = message_type->elements_count == 1 && message_type->elements[0].type->op == &asn_OP_SEQUENCE;
        const void *single_body = is_single_body ? member_value_ptr(&message_type->elements[0], message) : NULL;
        if (single_body) {
            *body_type_out = message_type->elements[0].type;
            *body_out = single_body;
        }
        return BODY_FOUND;
    }

    const asn_TYPE_descriptor_t *type = extensions_member->type;
    const void *value = member_value_ptr(extensions_member, message);
    if (!value || !choice_descend(&type, &value, BODY_CHOICE_MAX_DEPTH))
        return BODY_FUTURE;
    bool is_body = type->op == &asn_OP_SEQUENCE && !is_empty_sequence(type);
    if (!is_body)
        return BODY_FUTURE;
    *body_type_out = type;
    *body_out = value;
    return BODY_FOUND;
}

/* extension_slot_find: 본문의 nonCriticalExtension 사슬을 따라가 끝 빈 자리(SEQUENCE {})가 "있음"인지 봄.
 *   이유: 새 릴리스는 이 빈 자리를 켜고 그 뒤에 새 필드를 붙여, 17.3.0 문법으로 풀면 그 비트가 남음.
 *   반환: NONE(사슬 없음) / ABSENT(사슬 어딘가가 꺼짐) / PRESENT(끝 빈 자리까지 켜짐)
 */
static enum extension_slot extension_slot_find(const asn_TYPE_descriptor_t *body_type, const void *body) {
    const asn_TYPE_descriptor_t *type = body_type;
    const void *value = body;
    for (int i = 0; i < EXTENSION_CHAIN_MAX_LENGTH; i++) {
        const asn_TYPE_member_t *extension_member = member_by_name(type, "nonCriticalExtension");
        if (!extension_member)
            return EXTENSION_SLOT_NONE;
        const void *extension = member_value_ptr(extension_member, value);
        if (!extension)
            return EXTENSION_SLOT_ABSENT;
        if (is_empty_sequence(extension_member->type))
            return EXTENSION_SLOT_PRESENT;
        type = extension_member->type;
        value = extension;
    }
    return EXTENSION_SLOT_NONE;
}

// MARK: - 값 꺼내기

/* enum_value_take: ENUMERATED 값 → rrc_enum_value. 순번·이름은 asn1c 이름표에서 찾은 것만 씀.
 *   이유: 출력 층이 탐지 명세 철자("mo-Signalling", "nea0")를 asn1c 없이 만들게 이름까지 넘김.
 *   이름표에 없는 값(asn1c 가 모르는 확장 값에 넣는 표시 값 등)은 순번으로 믿지 않고 -1·NULL. 이름은 생성 코드의 고정 문자열
 */
static struct rrc_enum_value enum_value_take(const asn_TYPE_descriptor_t *type, long value) {
    struct rrc_enum_value enum_value = {.value = -1, .name = NULL};
    const asn_INTEGER_enum_map_t *entry = INTEGER_map_value2enum(type->specifics, value);
    if (!entry)
        return enum_value;
    enum_value.value = (int)entry->nat_value;
    enum_value.name = entry->enum_name;
    return enum_value;
}

/* bits_take: 크기가 고정된 BIT STRING → 정수(앞 비트가 높은 자리). 비트 수가 expected_bits 와 같을 때만 *value_out 을 채우고 true.
 *   이유: 문법의 SIZE 는 디코더가 지키지만, asn1c 판이 바뀌어 담는 모양이 달라져도 버퍼 밖을 읽지 않게 길이부터 봄.
 *   expected_bits 는 64 이하(ue-Identity 39, S-TMSI 48, Part2 9)
 */
static bool bits_take(const BIT_STRING_t *bits, size_t expected_bits, uint64_t *value_out) {
    size_t expected_bytes = (expected_bits + BYTE_BITS - 1) / BYTE_BITS;
    int unused_bits = (int)(expected_bytes * BYTE_BITS - expected_bits);
    bool is_valid = bits->buf
                 && bits->size == expected_bytes
                 && bits->bits_unused == unused_bits;
    if (!is_valid)
        return false;
    uint64_t value = 0;
    for (size_t i = 0; i < expected_bytes; i++)
        value = (value << BYTE_BITS) | bits->buf[i];
    *value_out = value >> unused_bits;
    return true;
}

/* values_take: 본문 타입으로 메시지를 가려 위 층이 쓰는 값을 rrc_msg 에 꺼냄. 꺼낼 값이 없는 메시지는 그대로 둠.
 *   이유: 본문은 body_find 가 이미 찾아 다시 내려가지 않고, 본문 타입이 정해지면 asn1c 구조체로 읽어 필드 이름을 컴파일러가 검사.
 *   값 하나가 문법과 다른 모양이면(비트 수 등) 그 값만 없음으로 둠. body 는 asn1c 트리를 빌림
 */
static void values_take(struct rrc_msg *rrc_msg, const asn_TYPE_descriptor_t *body_type, const void *body) {
    const NR_SecurityAlgorithmConfig_t *security_algorithm_config = NULL;
    if (body_type == &asn_DEF_NR_RRCSetupRequest_IEs) {
        const NR_RRCSetupRequest_IEs_t *setup_request = body;
        rrc_msg->establishment_cause = enum_value_take(&asn_DEF_NR_EstablishmentCause, setup_request->establishmentCause);
        const NR_InitialUE_Identity_t *ue_identity = &setup_request->ue_Identity;
        bool is_s_tmsi_part1 = ue_identity->present == NR_InitialUE_Identity_PR_ng_5G_S_TMSI_Part1;
        bool is_random_value = ue_identity->present == NR_InitialUE_Identity_PR_randomValue;
        if (is_s_tmsi_part1 && bits_take(&ue_identity->choice.ng_5G_S_TMSI_Part1, UE_IDENTITY_BITS, &rrc_msg->ue_identity))
            rrc_msg->ue_identity_type = RRC_UE_IDENTITY_NG_5G_S_TMSI_PART1;
        if (is_random_value && bits_take(&ue_identity->choice.randomValue, UE_IDENTITY_BITS, &rrc_msg->ue_identity))
            rrc_msg->ue_identity_type = RRC_UE_IDENTITY_RANDOM_VALUE;
    } else if (body_type == &asn_DEF_NR_RRCSetupComplete_IEs) {
        const NR_RRCSetupComplete_IEs_t *setup_complete = body;
        const struct NR_RRCSetupComplete_IEs__ng_5G_S_TMSI_Value *s_tmsi_value = setup_complete->ng_5G_S_TMSI_Value;
        bool is_full_s_tmsi = s_tmsi_value && s_tmsi_value->present == NR_RRCSetupComplete_IEs__ng_5G_S_TMSI_Value_PR_ng_5G_S_TMSI;
        bool is_s_tmsi_part2 = s_tmsi_value && s_tmsi_value->present == NR_RRCSetupComplete_IEs__ng_5G_S_TMSI_Value_PR_ng_5G_S_TMSI_Part2;
        uint64_t s_tmsi_part2 = 0;
        if (is_full_s_tmsi)
            rrc_msg->has_s_tmsi = bits_take(&s_tmsi_value->choice.ng_5G_S_TMSI, S_TMSI_BITS, &rrc_msg->s_tmsi);
        if (is_s_tmsi_part2 && bits_take(&s_tmsi_value->choice.ng_5G_S_TMSI_Part2, S_TMSI_PART2_BITS, &s_tmsi_part2)) {
            rrc_msg->has_s_tmsi_part2 = true;
            rrc_msg->s_tmsi_part2 = (uint16_t)s_tmsi_part2; // 9비트라 uint16_t 에 들어감
        }
    } else if (body_type == &asn_DEF_NR_RRCReject_IEs) {
        const NR_RRCReject_IEs_t *reject = body;
        bool is_wait_time_valid = reject->waitTime
                               && *reject->waitTime >= REJECT_WAIT_TIME_MIN_S
                               && *reject->waitTime <= REJECT_WAIT_TIME_MAX_S;
        if (is_wait_time_valid) {
            rrc_msg->has_wait_time = true;
            rrc_msg->wait_time_s = (uint8_t)*reject->waitTime;
        }
    } else if (body_type == &asn_DEF_NR_SecurityModeCommand_IEs) {
        const NR_SecurityModeCommand_IEs_t *security_mode_command = body;
        security_algorithm_config = &security_mode_command->securityConfigSMC.securityAlgorithmConfig;
    } else if (body_type == &asn_DEF_NR_RRCReconfiguration_IEs) {
        // radioBearerConfig.securityConfig.securityAlgorithmConfig 가 모두 있을 때만(셋 다 선택 필드)
        const NR_RRCReconfiguration_IEs_t *reconfiguration = body;
        bool has_security_config = reconfiguration->radioBearerConfig && reconfiguration->radioBearerConfig->securityConfig;
        if (has_security_config)
            security_algorithm_config = reconfiguration->radioBearerConfig->securityConfig->securityAlgorithmConfig;
    }

    // SecurityModeCommand·RRCReconfiguration 공통: 같은 SecurityAlgorithmConfig 모양
    if (!security_algorithm_config)
        return;
    rrc_msg->has_security_algorithm = true;
    rrc_msg->ciphering_algorithm = enum_value_take(&asn_DEF_NR_CipheringAlgorithm, security_algorithm_config->cipheringAlgorithm);
    if (security_algorithm_config->integrityProtAlgorithm)
        rrc_msg->integrity_algorithm = enum_value_take(&asn_DEF_NR_IntegrityProtAlgorithm, *security_algorithm_config->integrityProtAlgorithm);
}

// MARK: - 해석

/* msg_clear: rrc_msg 를 꺼낸 값이 없는 상태로 만듦. 0 이 올바른 값인 칸(ENUMERATED 순번)은 -1, channel 은 넘겨받은 값 */
static void msg_clear(struct rrc_msg *rrc_msg, enum rrc_channel channel) {
    memset(rrc_msg, 0, sizeof(*rrc_msg));
    rrc_msg->channel = channel;
    rrc_msg->establishment_cause.value = -1;
    rrc_msg->ciphering_algorithm.value = -1;
    rrc_msg->integrity_algorithm.value = -1;
    rrc_msg->reestablishment_cause.value = -1;
    rrc_msg->resume_cause.value = -1;
}

/* rrc_release: 트리 → 내부 상태 순으로 풀고, rrc_msg 의 포인터를 NULL·0 으로. 약속은 rrc.h */
void rrc_release(struct rrc_msg *rrc_msg) {
    if (!rrc_msg || !rrc_msg->internal)
        return;
    struct rrc_internal *internal = rrc_msg->internal;
    if (internal->message_type)
        ASN_STRUCT_FREE(*internal->message_type, internal->message); // message 가 NULL 이어도 됨(asn1c 가 확인)
    free(internal);
    rrc_msg->internal = NULL;
    rrc_msg->nas_pdu_count = 0;
    rrc_msg->nas_pdus = NULL;
    rrc_msg->segment_data = NULL;
    rrc_msg->segment_len = 0;
}

/* parse_fail: 해석 실패 처리. 잡은 것을 모두 해제하고 rrc_msg 를 값 없는 상태로 되돌림.
 *   이유: 실패하면 해제할 것이 없고 꺼낸 값도 남지 않는다는 rrc.h 의 약속을 실패하는 곳마다 같은 방법으로 지킴.
 *   반환: result 그대로
 */
static enum rrc_result parse_fail(struct rrc_msg *rrc_msg, enum rrc_result result) {
    enum rrc_channel channel = rrc_msg->channel;
    rrc_release(rrc_msg);
    msg_clear(rrc_msg, channel);
    return result;
}

/* rrc_parse: 푸는 방법 검사 → PDCP 떼기 → UPER 디코드 → 메시지 찾기 → 본문 찾기 → 남는 비트 판정 → 값 꺼내기.
 *   내부 상태를 잡은 뒤의 실패는 모두 parse_fail 로 끝냄. 약속(소유권·반환·실패 상태)은 rrc.h
 */
enum rrc_result rrc_parse(struct rrc_container_kind kind, const uint8_t *bytes, size_t len, struct rrc_msg *rrc_msg) {
    if (!rrc_msg)
        return RRC_DECODE_FAILED;
    const asn_TYPE_descriptor_t *message_type = channel_message_type(kind.channel);
    msg_clear(rrc_msg, message_type ? kind.channel : RRC_CHANNEL_NONE);

    // CCCH 는 SRB0 이라 PDCP 를 거치지 않음. CCCH 에 PDCP 모양이면 잘못 고른 것
    bool is_ccch = kind.channel == RRC_CHANNEL_UL_CCCH || kind.channel == RRC_CHANNEL_UL_CCCH1 || kind.channel == RRC_CHANNEL_DL_CCCH;
    bool is_plain = kind.encapsulation == RRC_ENCAPSULATION_NONE;
    bool is_pdcp = kind.encapsulation == RRC_ENCAPSULATION_PDCP && !is_ccch;
    bool is_valid_kind = message_type && (is_plain || is_pdcp);
    if (!is_valid_kind || !bytes || len == 0)
        return RRC_DECODE_FAILED;

    // PDCP 모양이면 머리·꼬리를 떼고 RRC 만. 최소 길이를 먼저 봐서 뺄셈이 0 아래로 내려가지 않게
    const uint8_t *rrc_bytes = bytes;
    size_t rrc_len = len;
    if (is_pdcp) {
        if (len < PDCP_MIN_BYTES)
            return RRC_DECODE_FAILED;
        rrc_bytes = bytes + PDCP_HEADER_BYTES;
        rrc_len = len - PDCP_HEADER_BYTES - PDCP_MAC_I_BYTES;
    }

    struct rrc_internal *internal = calloc(1, sizeof(*internal));
    if (!internal)
        return RRC_NO_MEMORY;
    internal->message_type = message_type;
    rrc_msg->internal = internal;

    // uper_decode 는 다 쓴 양을 비트로 돌려줌. 남은 비트로 4.5 의 판정을 함(uper_decode_complete 는 바이트로 돌려줘 쓰지 않음)
    const asn_codec_ctx_t decode_ctx = {.max_stack_size = DECODE_MAX_STACK_BYTES};
    asn_dec_rval_t decoded = uper_decode(&decode_ctx, message_type, &internal->message, rrc_bytes, rrc_len, 0, 0);
    if (decoded.code != RC_OK || decoded.consumed > rrc_len * BYTE_BITS)
        return parse_fail(rrc_msg, RRC_DECODE_FAILED);
    size_t trailing_bits = rrc_len * BYTE_BITS - decoded.consumed;

    const void *message = NULL;
    const asn_TYPE_descriptor_t *found_type = message_find(message_type, internal->message, &message);
    if (!found_type)
        return parse_fail(rrc_msg, RRC_UNKNOWN_MESSAGE);
    const asn_TYPE_descriptor_t *body_type = NULL;
    const void *body = NULL;
    if (body_find(found_type, message, &body_type, &body) == BODY_FUTURE)
        return parse_fail(rrc_msg, RRC_UNKNOWN_MESSAGE);

    // 채움(8비트 미만)을 넘어 남은 비트는 끝 빈 자리가 켜졌을 때만 새 릴리스 확장으로 받아들임. 그 밖은 의미 없는 바이트가 붙은 것
    bool has_unexplained_bits = trailing_bits >= BYTE_BITS && extension_slot_find(body_type, body) != EXTENSION_SLOT_PRESENT;
    if (has_unexplained_bits)
        return parse_fail(rrc_msg, RRC_DECODE_FAILED);

    values_take(rrc_msg, body_type, body);
    rrc_msg->msg_name = found_type->name;
    rrc_msg->trailing_bits = trailing_bits;
    return RRC_OK;
}

// MARK: - 채널 고르기 (F1AP)

/* rrc_kind_for_f1ap: F1AP 절차·PDU 종류·IE 번호·SRB ID·길이에서 채널과 바이트 모양을 고름. 약속은 rrc.h
 *   이유: 채널이 컨테이너 바이트에 적혀 있지 않음. SRB0 만 CCCH(평문)이고 SRB1~5 는 DCCH(PDCP PDU) (TS 38.331 §4.2.2, TS 38.473 §9.2.3)
 *   CU 가 받아들이는지, 메시지와 SRB 가 맞는지는 보지 않음(집계 층). 표 밖은 모두 NONE
 */
struct rrc_container_kind rrc_kind_for_f1ap(const struct f1ap_msg *f1ap_msg, const struct f1ap_rrc_container *container) {
    const struct rrc_container_kind none = {.channel = RRC_CHANNEL_NONE, .encapsulation = RRC_ENCAPSULATION_NONE};
    if (!f1ap_msg || !container)
        return none;

    // 절차 8 은 성공 응답(UE CONTEXT MODIFICATION CONFIRM)에, 나머지는 요청에만 RRC 메시지를 실음
    bool is_initiating = f1ap_msg->pdu_type == F1AP_PDU_INITIATING;
    bool is_modification_confirm = f1ap_msg->procedure_code == F1AP_PROCEDURE_UE_CONTEXT_MODIFICATION_REQUIRED
                                && f1ap_msg->pdu_type == F1AP_PDU_SUCCESSFUL;
    bool is_initial_ul = is_initiating && f1ap_msg->procedure_code == F1AP_PROCEDURE_INITIAL_UL_RRC_MESSAGE_TRANSFER;

    // IE 241 은 INITIAL UL RRC 의 PDCP 없는 RRCSetupComplete (TS 38.473 §9.2.3.1)
    const struct rrc_container_kind ul_dcch_plain = {.channel = RRC_CHANNEL_UL_DCCH, .encapsulation = RRC_ENCAPSULATION_NONE};
    if (container->ie_id == F1AP_IE_ID_RRC_CONTAINER_RRC_SETUP_COMPLETE)
        return is_initial_ul ? ul_dcch_plain : none;
    if (container->ie_id != F1AP_IE_ID_RRC_CONTAINER)
        return none;

    // CCCH 메시지는 크기 고정이라 8바이트만 UL-CCCH1. 그 밖 길이도 UL-CCCH 로 넘겨 rrc_parse 가 해석 실패로 남김(NONE 이면 흔적이 사라짐)
    enum rrc_channel ul_ccch_channel = container->len == UL_CCCH1_MESSAGE_BYTES ? RRC_CHANNEL_UL_CCCH1 : RRC_CHANNEL_UL_CCCH;
    const struct rrc_container_kind ul_ccch = {.channel = ul_ccch_channel, .encapsulation = RRC_ENCAPSULATION_NONE};
    const struct rrc_container_kind ul_dcch = {.channel = RRC_CHANNEL_UL_DCCH, .encapsulation = RRC_ENCAPSULATION_PDCP};
    const struct rrc_container_kind dl_ccch = {.channel = RRC_CHANNEL_DL_CCCH, .encapsulation = RRC_ENCAPSULATION_NONE};
    const struct rrc_container_kind dl_dcch = {.channel = RRC_CHANNEL_DL_DCCH, .encapsulation = RRC_ENCAPSULATION_PDCP};

    // SRB ID 가 있어야 하는 세 절차(UL·DL RRC MESSAGE TRANSFER, UE CONTEXT RELEASE COMMAND)용. 없음(-1)·0~5 밖은 둘 다 false
    bool is_ccch_srb = container->srb_id == SRB_ID_CCCH;
    bool is_dcch_srb = container->srb_id > SRB_ID_CCCH && container->srb_id <= SRB_ID_DCCH_MAX;

    if (is_modification_confirm)
        return dl_dcch;
    if (!is_initiating)
        return none;
    switch (f1ap_msg->procedure_code) {
    case F1AP_PROCEDURE_INITIAL_UL_RRC_MESSAGE_TRANSFER:
        return ul_ccch;
    case F1AP_PROCEDURE_UL_RRC_MESSAGE_TRANSFER:
        // SRB0 은 CG-SDT 의 RRCResumeRequest·RRCResumeRequest1
        if (is_ccch_srb)
            return ul_ccch;
        return is_dcch_srb ? ul_dcch : none;
    case F1AP_PROCEDURE_DL_RRC_MESSAGE_TRANSFER:
    case F1AP_PROCEDURE_UE_CONTEXT_RELEASE:
        // RELEASE COMMAND 는 컨테이너가 있으면 SRB ID 필수라 없으면 SRB1 로 짐작하지 않음
        if (is_ccch_srb)
            return dl_ccch;
        return is_dcch_srb ? dl_dcch : none;
    case F1AP_PROCEDURE_UE_CONTEXT_SETUP:
    case F1AP_PROCEDURE_UE_CONTEXT_MODIFICATION:
        return dl_dcch;
    default:
        return none;
    }
}
