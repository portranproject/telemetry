#ifndef TELEMETRY_AP_H
#define TELEMETRY_AP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// TODO: 집계·출력 층이 쓰게 되면 아래 두 타입(nr_cgi, reset_type)을 공용 헤더(예: src/common/types.h)로 옮김. 옮길 때 이름은 그대로

// nr_cgi: NR CGI(셀 전역 번호) = PLMN Identity + NR Cell Identity (TS 38.473). NGAP NR-CGI 도 같은 두 필드
struct nr_cgi {
    bool is_valid;             // NR CGI 가 있고 길이가 맞는지(PLMN 3바이트, 셀 번호 36비트). false 면 나머지 0
    uint8_t plmn_identity[3];  // 받은 바이트 그대로. MCC·MNC 숫자로 푸는 것은 쓰는 쪽
    uint64_t nr_cell_identity; // 36비트 셀 번호(위 28비트는 0)
};

// reset_type: RESET 의 범위. F1AP RESET 의 Reset Type·NGAP NG RESET 의 ResetType 과 같은 두 갈래
enum reset_type {
    RESET_TYPE_NONE = 0, // RESET 이 아니거나 범위를 모름(확장 갈래). 값 없음(0)
    RESET_TYPE_ALL,      // 모든 UE 연결 초기화(f1-Interface, NGAP nG-Interface)
    RESET_TYPE_PART,     // 목록의 UE 연결만 초기화(partOfF1-Interface, NGAP partOfNG-Interface)
};

// f1ap_rrc_container.ie_id 값. RRC 층·시험이 asn1c 헤더 없이 이름으로 비교하도록 둠
#define F1AP_IE_ID_RRC_CONTAINER 50                     // RRC-Container: RRC 메시지
#define F1AP_IE_ID_DU_TO_CU_RRC_CONTAINER 128           // DU to CU RRC Container: DU 가 만든 CellGroupConfig(RRC 메시지 아님)
#define F1AP_IE_ID_RRC_CONTAINER_RRC_SETUP_COMPLETE 241 // RRC-Container-RRCSetupComplete: INITIAL UL RRC MESSAGE TRANSFER 에 실리는 RRCSetupComplete

enum f1ap_result {
    F1AP_OK = 0,
    F1AP_DECODE_FAILED,   // 해석 실패, 남는 바이트, 입력 없음(NULL, 길이 0)
    F1AP_UNKNOWN_MESSAGE, // 해석은 됐지만 모르는 PDU 종류·절차. 의미 없는 바이트도 이렇게 해석돼 실패로 봄
    F1AP_NO_MEMORY,       // f1ap.c 의 할당 실패. asn1c 안의 할당 실패는 F1AP_DECODE_FAILED
};

// f1ap_pdu_type: 요청·성공 응답·실패 응답. 같은 절차 번호의 메시지를 가름. 0 = 값 없음
enum f1ap_pdu_type {
    F1AP_PDU_INITIATING = 1, // 절차를 시작하는 메시지(요청)
    F1AP_PDU_SUCCESSFUL,
    F1AP_PDU_UNSUCCESSFUL,
};

// ap_cause: Cause 의 범주·값(번호와 이름). NGAP 도 같이 씀
//   집계는 번호, 출력 층은 이름("radioNetwork:…")을 씀. 이름은 고정 문자열이라 f1ap_release 뒤에도 유효
struct ap_cause {
    bool is_present;
    int group;              // 범주 순번(문법 순서, 0부터): 0 radioNetwork, 1 transport, 2 protocol, 3 misc, 4 choice-extension. 없으면 -1(0 은 radioNetwork 라서)
    const char *group_name; // 예: "radioNetwork". 없으면 NULL
    int value;              // 범주 안 값 순번(예 10 = normal-release). 모르는 값이면 -1
    const char *value_name; // 예: "normal-release". value 가 -1 이면 NULL
};

// f1ap_rrc_container: RRC 컨테이너 하나. 바이트는 해석하지 않고 넘김
struct f1ap_rrc_container {
    int ie_id;           // F1AP_IE_ID_… 중 하나. RRC 메시지인지 CellGroupConfig 인지 가름
    int srb_id;          // 같은 메시지의 SRB ID. 채널(CCCH/DCCH) 고르기용. 없거나 DU to CU 컨테이너면 -1(0 은 SRB0)
    const uint8_t *data; // f1ap_release 전까지 유효
    size_t len;
};

// f1ap_reset_ue: 일부 RESET 목록의 UE 하나. 두 번호 모두 선택 필드라 둘 다 없을 수도 있음(그대로 넘김)
struct f1ap_reset_ue {
    bool has_cu_ue_id;
    uint32_t cu_ue_id;
    bool has_du_ue_id;
    uint32_t du_ue_id; // 탐지 f1_evt.du_ue_ids
};

// f1ap_internal: f1ap.c 전용 상태(트리·배열). asn1c 타입을 헤더에 두지 않으려고 이름만
struct f1ap_internal;

// f1ap_msg: F1AP PDU 하나에서 꺼낸 값. f1ap_parse 가 채우고 f1ap_release 가 해제
//   has_… 가 false 면 짝 값은 0. IE 가 없거나 값이 칸에 안 들어가면(음수, 32비트 초과) false
struct f1ap_msg {
    // 메시지 종류
    long procedure_code; // 0..255
    enum f1ap_pdu_type pdu_type;
    const char *msg_name; // 메시지 이름(예 "InitialULRRCMessageTransfer"). 고정 문자열이라 해제 뒤에도 유효

    // UE 식별(같은 UE 의 메시지 잇기)
    bool has_du_ue_id;
    uint32_t du_ue_id; // DU 가 UE 에 붙인 번호. 같은 UE 잇기의 기본 키
    bool has_cu_ue_id;
    uint32_t cu_ue_id; // CU 가 붙인 번호. INITIAL UL RRC 에는 없음(CU 가 아직 안 붙임)
    bool has_old_du_ue_id;
    uint32_t old_du_ue_id; // 재수립 때 옛 UE 와 새 UE 잇기(ReEstab)
    bool has_crnti;
    uint32_t crnti; // DU 가 UE 에 준 무선 구간 번호. Table I C-RNTI

    // 셀
    //   어느 메시지든 NR CGI IE 를 담음. 무슨 셀인지는 procedure_code 로 가림
    //   INITIAL UL RRC 면 UE 가 접속한 셀(탐지 cell_id). ACCESS SUCCESS 등 다른 메시지에도 실림
    struct nr_cgi nr_cgi;            // NR CGI IE 가 가리키는 셀
    bool has_du_to_cu_rrc_container; // INITIAL UL RRC 에 없으면 DU 가 UE 를 못 받는다는 뜻(탐지 ext.DuCannotServe)

    // 연결 수명
    struct ap_cause cause;      // 해제·실패 원인(UE CONTEXT RELEASE COMMAND·REQUEST 등). 탐지 증거
    enum reset_type reset_type; // RESET 에만 존재
    bool has_du_id;
    uint64_t du_id; // F1 SETUP REQUEST 의 DU 번호(0..2^36-1). 다시 붙은 DU 가 같은 DU 인지 가름

    // 배열(f1ap.c 가 할당, f1ap_release 가 해제). 개수 제한 없음
    int rrc_container_count;
    const struct f1ap_rrc_container *rrc_containers; // RRC 컨테이너 IE 전부(메시지 안 순서). 없으면 NULL
    int served_cell_count;
    const struct nr_cgi *served_cells; // F1 SETUP REQUEST 의 셀 목록(탐지 f1_evt.cells). 없으면 NULL
    int reset_ue_count;
    const struct f1ap_reset_ue *reset_ues; // 일부 RESET(partOfF1-Interface) 목록의 UE(메시지 안 순서). 없으면 NULL

    struct f1ap_internal *internal; // f1ap.c 전용(asn1c 트리·배열)
};

/* f1ap_parse: F1AP PDU 하나를 해석해 f1ap_msg 를 채움.
 *   이유: 위 층이 asn1c 를 몰라도 되게, 필요한 값만 asn1c 타입 없이 넘김.
 *   pdu_bytes 는 빌려 씀(돌아온 뒤 안 씀). 남는 바이트가 있으면 실패(F1AP_DECODE_FAILED).
 *   반환: F1AP_OK / F1AP_DECODE_FAILED / F1AP_UNKNOWN_MESSAGE / F1AP_NO_MEMORY.
 *   실패하면 값 없는 상태(has_… false, 개수 0, cause.group·value -1)이고 해제할 것 없음. f1ap_release 는 결과와 상관없이 불러도 됨.
 *   성공한 결과가 든 f1ap_msg 는 f1ap_release 한 뒤 다시 넘길 것(시작할 때 덮어써 앞 트리가 누수). 복사본을 따로 해제하면 두 번 해제.
 *   스레드: 한 번에 한 스레드만. asn1c 디코더가 모르는 IE·ENUMERATED 값을 만나면 잠금 없는 전역 계수기를 올림(asn1/asn1_glue.c).
 */
enum f1ap_result f1ap_parse(const uint8_t *pdu_bytes, size_t len, struct f1ap_msg *f1ap_msg);

/* f1ap_release: f1ap_parse 가 잡은 asn1c 트리와 배열을 해제.
 *   돌아온 뒤에는 rrc_containers·served_cells·reset_ues 와 그 안의 바이트 포인터가 무효(NULL·0 으로 바꿈).
 *   msg_name·cause 의 이름은 고정 문자열이라 그대로 유효.
 *   f1ap_msg 가 NULL 이거나 해제할 것이 없으면 아무것도 하지 않음. 두 번 불러도 됨.
 */
void f1ap_release(struct f1ap_msg *f1ap_msg);

#endif /* TELEMETRY_AP_H */
