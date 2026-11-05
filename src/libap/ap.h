#ifndef TELEMETRY_AP_H
#define TELEMETRY_AP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// TODO: 집계·출력 층이 쓰게 되면 아래 두 타입(nr_cgi, reset_type)을 공용 헤더(예: src/common/types.h)로 옮김. 옮길 때 이름은 그대로

// nr_cgi: NR CGI(셀 전역 번호) = PLMN Identity + NR Cell Identity (TS 38.473). NGAP NR-CGI 도 같은 두 필드
struct nr_cgi {
    bool is_valid;             // 메시지에 NR CGI 가 있고 두 필드 길이가 문법대로(PLMN 3바이트, 셀 번호 36비트)인지. false 면 나머지는 0
    uint8_t plmn_identity[3];  // 받은 바이트 그대로. MCC·MNC 숫자로 푸는 것은 쓰는 쪽
    uint64_t nr_cell_identity; // BIT STRING 36비트를 하위 36비트에. 위 28비트는 0
};

// reset_type: RESET 의 범위. F1AP RESET 의 Reset Type·NGAP NG RESET 의 ResetType 과 같은 두 갈래
enum reset_type {
    RESET_TYPE_NONE = 0, // RESET 이 아닌 메시지 또는 문법의 확장 갈래(choice-extension). 0 으로 채운 구조체의 값
    RESET_TYPE_ALL,      // f1-Interface(NGAP nG-Interface): 그 인터페이스의 모든 UE 연결 초기화
    RESET_TYPE_PART,     // partOfF1-Interface(NGAP partOfNG-Interface): 목록에 적힌 UE 연결만 초기화
};

// f1ap_rrc_container.ie_id 값. RRC 층·시험이 asn1c 헤더 없이 이름으로 비교하도록 둠
#define F1AP_IE_ID_RRC_CONTAINER 50                     // RRC-Container: RRC 메시지
#define F1AP_IE_ID_DU_TO_CU_RRC_CONTAINER 128           // DU to CU RRC Container: DU 가 만든 CellGroupConfig(RRC 메시지 아님)
#define F1AP_IE_ID_RRC_CONTAINER_RRC_SETUP_COMPLETE 241 // RRC-Container-RRCSetupComplete: INITIAL UL RRC MESSAGE TRANSFER 에 실리는 RRCSetupComplete

enum f1ap_result {
    F1AP_OK = 0,
    F1AP_DECODE_FAILED,   // APER 해석 실패, 해석 뒤 남는 바이트, 입력 없음(pdu_bytes·f1ap_msg 가 NULL, len 0)
    F1AP_UNKNOWN_MESSAGE, // 해석은 됐지만 PDU 종류가 확장 갈래(choice-extension)이거나 문법이 모르는 절차. 의미 없는 바이트가 이 모양으로 해석될 수 있어 실패로 봄
    F1AP_NO_MEMORY,       // f1ap.c 가 잡는 내부 상태·결과 배열. asn1c 디코드 안의 할당 실패는 F1AP_DECODE_FAILED 로 나옴
};

// f1ap_pdu_type: F1AP-PDU 의 세 갈래. 같은 절차 번호의 요청과 응답을 가름. 0 은 비워 두어 값이 없는 상태를 구분
enum f1ap_pdu_type {
    F1AP_PDU_INITIATING = 1, // 절차를 시작하는 메시지(요청)
    F1AP_PDU_SUCCESSFUL,
    F1AP_PDU_UNSUCCESSFUL,
};

// ap_cause: NGAP Cause 도 같은 모양이라 같이 씀
//   이름은 asn1c 이름표(문법의 ASN.1 이름)를 가리키는 고정 문자열이라 f1ap_release 뒤에도 유효.
//   번호와 이름을 둘 다 두는 이유: 집계는 번호로 세고, 출력 층은 이름으로 탐지 명세의 "radioNetwork:…" 문자열을 만듦
struct ap_cause {
    bool is_present;
    int group;              // 범주 순번(문법 순서, 0부터): 0 radioNetwork, 1 transport, 2 protocol, 3 misc, 4 choice-extension. 없으면 -1(0 은 radioNetwork 라서)
    const char *group_name; // 예: "radioNetwork". 없으면 NULL
    int value;              // 범주 안 값 순번. 예: radioNetwork 의 10 = normal-release. 문법이 모르는 확장값·choice-extension 이면 -1
    const char *value_name; // 예: "normal-release". value 가 -1 이면 NULL
};

struct f1ap_rrc_container {
    int ie_id;           // 담긴 IE: F1AP_IE_ID_RRC_CONTAINER 등(위 상수). RRC 층이 RRC 메시지와 CellGroupConfig 를 가름
    int srb_id;          // 같은 메시지의 SRB ID. RRC 층이 procedure_code 와 함께 채널(CCCH/DCCH)을 고름. 없거나 IE 128 이면 -1(0 은 SRB0 이라서)
    const uint8_t *data; // f1ap_release 전까지 유효
    size_t len;
};

// f1ap_internal: f1ap_parse 가 잡은 asn1c 트리·배열. 안의 모양은 f1ap.c 에만 두고 밖에는 포인터로만 둠(asn1c 타입을 이 헤더에 넣지 않으려고)
struct f1ap_internal;

// f1ap_msg: F1AP PDU 하나에서 꺼낸 값. f1ap_parse 가 채우고 f1ap_release 가 해제
//   has_… 가 false 면 짝 값은 0
struct f1ap_msg {
    // 메시지 종류
    long procedure_code; // 0..255
    enum f1ap_pdu_type pdu_type;
    const char *msg_name; // asn1c 타입 이름. 고정 문자열이라 f1ap_release 뒤에도 유효

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
    //   nr_cgi 는 메시지 종류와 상관없이 NR CGI IE 를 담으므로, 무슨 셀인지는 procedure_code 로 가림.
    //   INITIAL UL RRC 에서는 UE 가 접속한 셀(탐지 명세 cell_id). ACCESS SUCCESS, CELL SWITCH NOTIFICATION,
    //   SYSTEM INFORMATION DELIVERY COMMAND 등에도 실리며 그때의 뜻은 그 메시지가 정함
    struct nr_cgi nr_cgi;            // NR CGI IE 가 가리키는 셀
    bool has_du_to_cu_rrc_container; // INITIAL UL RRC 에 없으면 DU 가 그 UE 를 받을 수 없다는 뜻. 탐지 명세 ext.DuCannotServe

    // 연결 수명
    struct ap_cause cause;      // UE CONTEXT RELEASE COMMAND·REQUEST 등. 연결 실패 원인 보조, 탐지 증거
    enum reset_type reset_type; // RESET 에만 존재
    bool has_du_id;
    uint64_t du_id; // (0..2^36-1). F1 SETUP REQUEST. DU 가 여러 개일 때 재시작해 새 연결로 붙은 DU 가 같은 DU 인지 확인

    // 배열(f1ap.c 가 할당, f1ap_release 가 해제). 개수 제한 없음
    int rrc_container_count;
    const struct f1ap_rrc_container *rrc_containers; // IE 50·241·128 전부, 메시지 안 순서대로. 없으면 NULL
    int served_cell_count;
    const struct nr_cgi *served_cells; // gNB-DU Served Cells List 의 항목마다 NR CGI. F1 SETUP REQUEST. 그 DU 의 셀 목록(탐지 명세 f1_evt.cells). 없으면 NULL

    struct f1ap_internal *internal; // f1ap.c 전용(asn1c 트리·배열)
};

/* f1ap_parse: F1AP PDU 하나를 해석해 f1ap_msg 에 값을 채움.
 *   이유: Table I·II 와 탐지에 쓰는 값만 asn1c 타입 없이 넘겨, 위 층이 asn1c 를 몰라도 되게 함.
 *   pdu_bytes 는 호출한 쪽 소유. 돌아온 뒤에는 쓰지 않음(필요한 바이트는 asn1c 트리에 복사됨).
 *   PDU 를 정확히 다 써야 성공(남는 바이트가 있으면 F1AP_DECODE_FAILED).
 *   반환: F1AP_OK / F1AP_DECODE_FAILED / F1AP_UNKNOWN_MESSAGE / F1AP_NO_MEMORY.
 *   실패하면 f1ap_msg 는 꺼낸 값이 없는 상태(has_… false, 개수 0, cause.group·value -1)이고 해제할 것도 없음.
 *   결과와 상관없이 f1ap_release 를 불러도 됨.
 */
enum f1ap_result f1ap_parse(const uint8_t *pdu_bytes, size_t len, struct f1ap_msg *f1ap_msg);

/* f1ap_release: f1ap_parse 가 잡은 asn1c 트리와 배열을 해제.
 *   돌아온 뒤에는 rrc_containers·served_cells 와 그 안의 바이트 포인터가 무효(NULL·0 으로 바꿈).
 *   msg_name·cause 의 이름은 고정 문자열이라 그대로 유효.
 *   f1ap_msg 가 NULL 이거나 해제할 것이 없으면 아무것도 하지 않음. 두 번 불러도 됨.
 */
void f1ap_release(struct f1ap_msg *f1ap_msg);

#endif /* TELEMETRY_AP_H */
