#ifndef TELEMETRY_RRC_H
#define TELEMETRY_RRC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "libap/ap.h"

// rrc_channel: RRC 메시지를 실은 논리 채널. 어느 문법 최상위 타입(UL-CCCH-Message 등)으로 풀지 정함
enum rrc_channel {
    RRC_CHANNEL_NONE = 0, // 고르지 못함(RRC 메시지가 아닌 컨테이너, 규칙에 없는 조합). 풀지 않음
    RRC_CHANNEL_UL_CCCH,  // SRB0 상향: RRCSetupRequest·RRCResumeRequest·RRCReestablishmentRequest(6바이트)
    RRC_CHANNEL_UL_CCCH1, // SRB0 상향 8바이트: RRCResumeRequest1
    RRC_CHANNEL_UL_DCCH,  // SRB1·2 상향: RRCSetupComplete·SecurityModeComplete·ULInformationTransfer 등
    RRC_CHANNEL_DL_CCCH,  // SRB0 하향: RRCSetup·RRCReject
    RRC_CHANNEL_DL_DCCH,  // SRB1·2 하향: SecurityModeCommand·RRCReconfiguration·RRCRelease 등
};

// rrc_encapsulation: RRC 바이트의 모양
//   F1AP 는 같은 UL-DCCH 메시지를 PDCP 에 싸서(IE 50) 싣기도, 그냥(IE 241) 싣기도 해 채널만으로 정할 수 없음
enum rrc_encapsulation {
    RRC_ENCAPSULATION_NONE = 0, // RRC 메시지 바이트만: CCCH, F1AP IE 241, 분할 조각을 합친 바이트
    RRC_ENCAPSULATION_PDCP,     // PDCP 데이터 PDU = 머리 2바이트 + RRC + MAC-I 4바이트. F1AP IE 50 의 DCCH
};

// rrc_container_kind: RRC 바이트를 푸는 방법(채널 + 바이트 모양)
//   rrc_kind_for_f1ap 가 정하거나, 분할 조각을 합친 쪽이 { RRC_CHANNEL_UL_DCCH, RRC_ENCAPSULATION_NONE } 으로 줌
struct rrc_container_kind {
    enum rrc_channel channel;
    enum rrc_encapsulation encapsulation;
};

enum rrc_result {
    RRC_OK = 0,
    RRC_DECODE_FAILED,   // 입력 없음·길이 부족, UPER 해석 실패, 확장 표시 없이 남는 바이트, NAS 개수가 문법 상한 초과. asn1c 안의 할당 실패도 여기
    RRC_UNKNOWN_MESSAGE, // 해석은 됐지만 spare·지원하지 않는 확장 갈래·criticalExtensionsFuture. 뜻 있는 메시지로 보지 않음
    RRC_NO_MEMORY,       // rrc.c 의 할당 실패
};

// rrc_enum_value: 문법 ENUMERATED 값 하나. 순번과 ASN.1 이름
//   출력 층이 asn1c 없이 탐지 명세 철자("mo-Signalling", "nea0")를 쓰도록 이름도 둠. 이름은 고정 문자열이라 rrc_release 뒤에도 유효
struct rrc_enum_value {
    int value;        // 문법 순서의 순번(0부터). 없거나 모르는 확장 값이면 -1(0 은 첫 값이라서)
    const char *name; // 예: "mo-Signalling". value 가 -1 이면 NULL
};

// rrc_ue_identity_type: RRCSetupRequest 의 ue-Identity 갈래. 0 = 없음
enum rrc_ue_identity_type {
    RRC_UE_IDENTITY_NONE = 0,
    RRC_UE_IDENTITY_NG_5G_S_TMSI_PART1, // 5G-S-TMSI 의 하위 39비트. 단말 키(탐지 AN-07 등)
    RRC_UE_IDENTITY_RANDOM_VALUE,       // 단말이 고른 39비트 난수. 단말을 가리키는 값이 아님
};

// rrc_nas_pdu: RRC 메시지에 실린 NAS 메시지 하나. 해석하지 않고 넘김
struct rrc_nas_pdu {
    const uint8_t *data; // rrc_release 전까지 유효. len 이 0 이면 NULL 일 수 있음
    size_t len;          // 0 도 넘김. 버리면 이상한 입력이 있었다는 사실이 NAS 층에서 사라짐
};

// rrc_internal: rrc.c 전용 상태(asn1c 트리·배열). asn1c 타입을 헤더에 두지 않으려고 이름만
struct rrc_internal;

// rrc_msg: RRC 메시지 하나에서 꺼낸 값. rrc_parse 가 채우고 rrc_release 가 해제
//   has_… 가 false 면 짝 값은 0. 메시지별 칸은 그 메시지일 때만 채움
struct rrc_msg {
    // 메시지 종류
    enum rrc_channel channel; // 푼 채널(받은 kind 그대로). 방향(UL·DL)도 여기서 앎
    const char *msg_name;     // ASN.1 타입 이름(예 "RRCSetupRequest"). 탐지 명세 msg 철자. 고정 문자열이라 해제 뒤에도 유효
    size_t trailing_bits;     // 진단용: 풀고 남은 비트 수. 8 이상이면 새 릴리스 확장이 붙은 것. 이 값으로 암호문인지 판단하지 않음

    // RRCSetupRequest
    struct rrc_enum_value establishment_cause; // 탐지 est_cause, 표 II 원인별 세분
    enum rrc_ue_identity_type ue_identity_type;
    uint64_t ue_identity; // 39비트 값. 종류는 ue_identity_type

    // RRCSetupComplete
    bool has_s_tmsi;
    uint64_t s_tmsi; // ng-5G-S-TMSI 48비트. 탐지 s_tmsi, 표 I S-TMSI
    bool has_s_tmsi_part2;
    uint16_t s_tmsi_part2; // 48비트 대신 9비트만 올 때. RRCSetupRequest 의 Part1 과 합치는 것은 집계 층

    // RRCReject
    bool has_wait_time;
    uint8_t wait_time_s; // 1~16초. 탐지 wait_time

    // SecurityModeCommand, RRCReconfiguration(radioBearerConfig.securityConfig 의 securityAlgorithmConfig)
    bool has_security_algorithm;
    struct rrc_enum_value ciphering_algorithm; // 예 "nea0". 표 I Cipher Algorithm, 탐지 cipher
    struct rrc_enum_value integrity_algorithm; // 예 "nia2". 문법상 선택 필드라 없으면 -1·NULL. 표 I Integrity Algorithm, 탐지 integrity

    // RRCRelease
    bool has_suspend_config;       // INACTIVE 로 보냄. 탐지 suspend, 표 II RelWithoutSuspendConfig·InactiveConn
    uint64_t suspend_full_i_rnti;  // 40비트. 나중의 RRCResumeRequest1 과 잇기
    uint32_t suspend_short_i_rnti; // 24비트. 나중의 RRCResumeRequest 와 잇기. full 의 하위 24비트라고 가정하지 않음

    // RRCReestablishmentRequest
    struct rrc_enum_value reestablishment_cause; // 표 II ReEstab
    bool has_old_ue_identity;
    uint16_t old_crnti; // 0~65535. 옛 연결을 찾는 단서일 뿐(C-RNTI 는 셀마다 다시 씀)
    uint16_t old_pci;   // 0~1007. 옛 셀의 물리 셀 번호

    // RRCResumeRequest, RRCResumeRequest1
    struct rrc_enum_value resume_cause; // 표 II Resume
    bool has_resume_i_rnti;
    bool is_full_resume_i_rnti; // true = 40비트(RRCResumeRequest1), false = 24비트(RRCResumeRequest)
    uint64_t resume_i_rnti;

    // ULDedicatedMessageSegment-r16: 분할된 UL-DCCH 메시지(예 UECapabilityInformation)의 조각
    bool has_segment;
    uint8_t segment_number;      // 0~15
    bool is_last_segment;        // true 면 모은 조각을 이어 붙여 { UL-DCCH, NONE } 으로 다시 풀 차례
    const uint8_t *segment_data; // PDCP 없는 UL-DCCH 메시지의 일부. rrc_release 전까지 유효라 모을 때는 복사
    size_t segment_len;

    // NAS 배열(rrc.c 가 할당, rrc_release 가 해제)
    int nas_pdu_count;
    const struct rrc_nas_pdu *nas_pdus; // 메시지 안 순서. 없으면 NULL

    struct rrc_internal *internal; // rrc.c 전용(asn1c 트리·배열)
};

/* rrc_kind_for_f1ap: F1AP 메시지에 실린 RRC 컨테이너를 어떻게 풀지(채널·바이트 모양) 정함.
 *   이유: 채널은 컨테이너 바이트에 적혀 있지 않고, 실어 나른 F1AP 메시지·IE·SRB ID 로 정해짐 (TS 38.473 §9.2.3).
 *   규칙은 RRC 지시서 4.4 표. 표에 없는 조합, RRC 메시지가 아닌 컨테이너(IE 128), NULL 인자면 channel 이 RRC_CHANNEL_NONE.
 *   f1ap_msg·container 는 빌려 씀.
 */
struct rrc_container_kind rrc_kind_for_f1ap(const struct f1ap_msg *f1ap_msg, const struct f1ap_rrc_container *container);

/* rrc_parse: RRC 바이트 하나를 kind 대로 풀어 rrc_msg 를 채움.
 *   이유: 위 층이 asn1c 를 몰라도 되게, 필요한 값만 asn1c 타입 없이 넘김. F1AP 와 무관하게 바이트만 받음.
 *   bytes 는 빌려 씀(돌아온 뒤 안 씀). NAS·조각 포인터는 bytes 가 아니라 asn1c 트리를 가리켜 rrc_release 전까지 유효.
 *   반환: RRC_OK / RRC_DECODE_FAILED / RRC_UNKNOWN_MESSAGE / RRC_NO_MEMORY.
 *   실패하면 값 없는 상태(has_… false, 순번 -1, 개수 0)이고 해제할 것 없음. rrc_release 는 결과와 상관없이 불러도 됨.
 *   성공한 결과가 든 rrc_msg 는 rrc_release 한 뒤 다시 넘길 것(시작할 때 덮어써 앞 트리가 누수). 복사본을 따로 해제하면 두 번 해제.
 *   평문인지는 판단하지 않음: 암호문도 우연히 풀릴 수 있어, 믿을지는 위 층이 그 UE 의 보안 상태로 정함.
 *   스레드: 한 번에 한 스레드만(여러 스레드는 검증 안 함).
 */
enum rrc_result rrc_parse(struct rrc_container_kind kind, const uint8_t *bytes, size_t len, struct rrc_msg *rrc_msg);

/* rrc_release: rrc_parse 가 잡은 asn1c 트리와 NAS 배열을 해제.
 *   돌아온 뒤에는 nas_pdus·segment_data 와 그 안의 바이트 포인터가 무효(NULL·0 으로 바꿈).
 *   msg_name·rrc_enum_value 의 이름은 고정 문자열이라 그대로 유효.
 *   rrc_msg 가 NULL 이거나 해제할 것이 없으면 아무것도 하지 않음. 두 번 불러도 됨.
 */
void rrc_release(struct rrc_msg *rrc_msg);

#endif /* TELEMETRY_RRC_H */
