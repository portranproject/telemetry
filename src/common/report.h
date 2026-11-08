#ifndef TELEMETRY_REPORT_H
#define TELEMETRY_REPORT_H

// 집계 층(obs·tr)이 출력 층(sink)에 넘기는 값. 탐지 명세의 ue_evt·f1_evt·kpm2 한 줄과 필드가 1:1 이다.
//   이 파일은 표준 헤더만 include 하고, 해석기(libap·librrc·libnas)는 이 파일을 include 하지 않는다 —
//   이벤트 모양이 바뀌어도 해석기가 다시 빌드되지 않게.
//   값이 없을 수 있는 번호는 has_… 짝으로 가린다(0 도 정상 값인 번호가 많아서). 문자열·배열은 빌려 쓰는 포인터라
//   sink 호출이 돌아올 때까지만 유효하다. 열거형의 0 은 '없음'이라, 채우지 않은 채 넘기면 sink 가 그 줄을 내지 않는다.

#include <stdbool.h>
#include <stdint.h>

// report_direction: 메시지 방향. 탐지 ue_evt.dir
enum report_direction {
    REPORT_DIRECTION_NONE = 0, // 채우지 않음. 탐지 엔진은 dir 없는 줄을 버리므로 sink 가 내지 않음
    REPORT_DIRECTION_UL,       // 단말 → 망
    REPORT_DIRECTION_DL,       // 망 → 단말
};

// report_proto: 메시지가 속한 계층. 탐지 ue_evt.proto
enum report_proto {
    REPORT_PROTO_NONE = 0,
    REPORT_PROTO_RRC,
    REPORT_PROTO_NAS,
    REPORT_PROTO_F1AP,
};

// report_nas_via: NAS 를 본 경로. 탐지 ue_evt.via — NAS 줄에만 있음
//   같은 NAS 를 F1·NGAP 양쪽에서 보면 obs 가 F1 쪽 1줄만 넘김(탐지 명세 §6.2). sink 는 받은 대로 씀
enum report_nas_via {
    REPORT_NAS_VIA_NONE = 0,
    REPORT_NAS_VIA_F1,   // RRC 에 실린 NAS(F1-C). 시각도 F1 에서 본 시각
    REPORT_NAS_VIA_NGAP, // NGAP 에서만 본 NAS(AS 암호 구간 등). du_ue_id 를 모를 수 있는 유일한 줄
};

// report_f1_kind: f1_evt 종류. 탐지 f1_evt.msg 의 두 값
enum report_f1_kind {
    REPORT_F1_KIND_NONE = 0,
    REPORT_F1_KIND_SETUP, // F1 SETUP REQUEST → "F1SetupRequest". 탐지 엔진이 그 DU 셀들의 UE 상태를 비움
    REPORT_F1_KIND_RESET, // RESET → "F1Reset"
};

// report_ue_fields: 메시지 안에서 꺼낸 값. 탐지 ue_evt.f — 메시지마다 쓰는 키가 다르고, 값이 없으면 sink 가 그 키를 뺌
//   이름 철자·번호는 해석기가 준 그대로. 탐지 철자로 바꾸는 표(NAS 이름·reg_type·id_type·NAS 알고리즘)는 sink 안에 있음
struct report_ue_fields {
    bool has_est_cause;
    const char *est_cause; // RRCSetupRequest establishmentCause 의 ASN.1 이름(예 "mo-Signalling"). 탐지 철자와 같음. 빌림 — 호출 동안만 유효

    bool has_ue_identity;       // RRCSetupRequest ue-Identity
    bool is_ue_identity_part1;  // true: ng-5G-S-TMSI-Part1(아래 39비트) / false: randomValue(값은 보내지 않음)
    uint64_t ue_identity_part1; // 5G-S-TMSI 하위 39비트. 탐지 "0x" + 10자리

    bool has_wait_time;
    uint32_t wait_time_s; // RRCReject waitTime(초)

    bool has_s_tmsi;
    uint64_t s_tmsi; // 5G-S-TMSI 48비트. 탐지 명세는 RRCSetupComplete·RegistrationRequest·ServiceRequest·RegistrationAccept 에서만 읽음 — 그 밖 메시지면 sink 가 키를 뺌
    bool has_s_tmsi_part2;
    uint32_t s_tmsi_part2; // RRCSetupComplete 에 Part2 만 있을 때 9비트. 48비트를 합쳤으면 s_tmsi 로

    bool has_rrc_algorithm; // RRC SecurityModeCommand
    const char *cipher;     // ASN.1 이름 그대로(예 "nea0"). 빌림 — 호출 동안만 유효
    const char *integrity;  // 예 "nia2". 문법상 선택 필드라 없으면 NULL. 빌림 — 호출 동안만 유효

    bool has_nas_algorithm;      // NAS SecurityModeCommand
    int nas_ciphering_algorithm; // TS 24.501 9.11.3.34 니블 값 0~7. sink 가 0~3 만 "5G-EA0"~"5G-EA3" 으로 씀(탐지 명세에 없는 예약값은 키 뺌)
    int nas_integrity_algorithm; // 같음. "5G-IA0"~"5G-IA3"

    bool has_suspend;
    bool suspend; // RRCRelease 에 suspendConfig 가 있는지

    bool has_reg_type;
    int reg_type; // RegistrationRequest 등록 유형(TS 24.501 9.11.3.7 하위 3비트). sink 가 1~4 → "initial"·"mobility"·"periodic"·"emergency", 0 은 initial 로

    int id_type; // 5GS mobile identity 종류(TS 24.501 표 9.11.3.4.1 의 3비트 값 0~7). 못 읽었으면 -1
                 //   has_ 짝 없이 정수인 이유: 표의 여덟 값 전부에 뜻이 있어 '못 읽음(-1)' 과 'No identity(0)' 를 나눠야 함
                 //   sink 는 RegistrationRequest 줄에서만 1 SUCI·2 5G-GUTI·3 IMEI·5 IMEISV 를 탐지 이름으로 쓰고 나머지는 키를 뺌

    bool has_nas_cause;
    int nas_cause; // 5GMM 원인(TS 24.501 9.11.3.2). 탐지 명세는 정수 그대로(AuthenticationFailure 21 = 동기 실패)

    bool has_f1ap_cause;          // F1AP Cause → 탐지 "<범주>:<값 이름>"
    const char *f1ap_cause_group; // 예 "radioNetwork". 빌림 — 호출 동안만 유효
    const char *f1ap_cause_value; // 예 "normal-release". 빌림 — 호출 동안만 유효

    bool has_switch_off;
    bool switch_off; // UE 발신 DeregistrationRequest 의 Switch off 비트. 망 발신은 그 비트가 spare 라 값 없음
};

// report_ue_event: UE 에 묶인 메시지 하나. 탐지 ue_evt 한 줄
//   obs 가 UE 잇기를 끝낸 뒤 넘김: du_ue_id·crnti·cell_id 는 그 UE 의 모든 메시지에 붙음(탐지 명세 §6.2)
struct report_ue_event {
    uint64_t t_ms;    // 관측 시각(Unix epoch ms, 캡처 시각 ns 를 내림). 칸 경계와 같은 시계
    uint64_t cell_id; // tr 이 (PLMN + NR Cell Identity) 마다 처음 본 순서로 1부터 매긴 번호, 세션 동안 고정. 탐지 엔진이 int64 로 읽어 64비트

    bool has_du_ue_id; // false 는 NGAP 에서만 본 NAS 줄(via NGAP)만 됨 — 그 밖은 sink 가 내지 않음
    uint32_t du_ue_id; // gNB-DU UE F1AP ID. UE 를 잇는 기본 키
    bool has_cu_ue_id; // CU 가 첫 DL 을 보내기 전(RRCSetupRequest 줄)에는 없음 → 키 뺌
    uint32_t cu_ue_id; // gNB-CU UE F1AP ID
    bool has_crnti;    // 모르면 탐지에 null 로 나감(키는 늘 있음)
    uint32_t crnti;    // INITIAL UL RRC MESSAGE TRANSFER 의 C-RNTI

    enum report_direction direction;
    enum report_proto proto;

    const char *msg_name;    // RRC·F1AP: 해석기가 준 ASN.1 타입 이름(예 "RRCSetupRequest", "UEContextReleaseCommand"). 탐지 철자와 같음. NAS 면 NULL. 빌림 — 호출 동안만 유효
    int nas_epd;             // NAS: 확장 프로토콜 판별자(0x7e 5GMM). sink 이름표의 키
    int nas_msg_type;        // NAS: 메시지 타입. 안쪽을 못 읽었으면 -1 → "ProtectedNAS"
    enum report_nas_via via; // NAS 만
    int sht;                 // NAS 만: 바깥 보안 헤더 타입 0~4. 없으면 -1(탐지 엔진은 sht 없는 NAS 줄을 버리므로 sink 가 내지 않음)

    struct report_ue_fields fields; // 탐지 f. 값이 하나도 없으면 sink 가 f 키를 뺌
};

// report_f1_event: DU 연결 수준 사건. 탐지 f1_evt 한 줄 — 탐지 엔진이 그 셀들의 UE 상태를 비움
struct report_f1_event {
    uint64_t t_ms;
    enum report_f1_kind kind;
    bool cells_known;         // false 면 탐지 cells null(= 모든 셀). true 이고 cell_count 0 이면 [](아무것도 닫지 않음)
    const uint64_t *cell_ids; // 그 DU 의 셀 번호(cell_id 와 같은 번호). cell_count 개. 빌림 — 호출 동안만 유효
    int cell_count;
    const uint32_t *du_ue_ids; // 일부 UE 만 대상(RESET partOfF1-Interface)이면 그 목록. NULL 이면 전체. 빌림 — 호출 동안만 유효
    int du_ue_id_count;
};

// report_cause_count: 원인별 카운터 한 칸. 탐지 원인별 객체에서 total 을 뺀 키 하나
struct report_cause_count {
    const char *name; // 원인 이름(RRC establishmentCause ASN.1 철자, 예 "mo-Signalling"). 탐지 철자와 같음. 빌림 — 호출 동안만 유효
    uint32_t count;   // 0 인 원인은 넘기지 않음 — 탐지 명세는 0 이 아닌 원인만 쓰고 합이 total 과 같아야 함
};

// report_counter: 카운터 하나. 탐지 kpm2 의 {"total":n, "<원인>":m, …} 또는 null
struct report_counter {
    bool is_counted;                         // false 면 null(세지 못함 — 예: 재개 완료가 F1 에서 안 보이는 배치). 0 은 '셌고 0건' 이라 따로 둠
    uint32_t total;                          // 탐지에 쓰는 값
    uint32_t inferred;                       // 직접 보지 못하고 추정으로 메운 수(total 에 든 일부). 수동 관측이라 생기는 칸 — 탐지 명세에 이 키가 없어 줄에는 안 쓰고 sink 통계에만 더함
    const struct report_cause_count *causes; // 원인별 세분. 없으면 NULL. 빌림 — 호출 동안만 유효
    int cause_count;
};

// report_period: 셀 하나의 100 ms 칸 결과. 탐지 kpm2 한 줄
//   tr 이 칸을 닫을 때 넘김. 그 칸에 드는 ue_evt 는 이미 다 넘어온 뒤(탐지 명세 §6.5 순서는 obs·tr 호출 순서가 보장)
struct report_period {
    uint64_t cell_id;
    uint64_t t_start_ms; // 칸 [t_start_ms, t_end_ms). 길이는 늘 period_ms
    uint64_t t_end_ms;

    bool is_capture_alive; // false 면 cc·si·ext 를 모두 null(탐지 명세 §5.3: 캡처가 멈췄거나 확인되지 않은 칸을 0 으로 채우면 조용한 정상 셀로 보임)
                           //   tr_set_capture_alive 로 받은 값 — 초기값 '모름' 과, 주기 안에서 한 번이라도 false 면 그 주기 전체가 false

    // cc 의 원인별 객체. RRC.ConnEstabAtt·Succ, UECNTX.ConnEstabAtt·Succ, RRC.ResumeAtt·Succ
    struct report_counter conn_estab_att;
    struct report_counter conn_estab_succ;
    struct report_counter uectx_estab_att;
    struct report_counter uectx_estab_succ;
    struct report_counter resume_att; // 지금은 세지 못해 is_counted false
    struct report_counter resume_succ;

    bool has_fail_cause;     // RRC.ConnEstabFailCause. 셋을 한 객체로 — 탐지 명세는 셋 다 넣음
    uint32_t network_reject; // RRCReject
    uint32_t no_reply;       // RRCSetup 뒤 noreply_timeout_ms 안에 RRCSetupComplete 없음
    uint32_t other;

    bool has_rel_without_suspend;
    uint32_t rel_without_suspend; // suspendConfig 없는 RRCRelease

    bool has_reestab; // RRC.ReEstabAtt·ReEstabSuccWithUeContext. 지금은 false → null
    uint32_t reestab_att;
    uint32_t reestab_succ;

    // si. 칸 끝 표본(si_sample_ms = period_ms)
    bool has_conn_si;             // RRC.ConnMean·ConnMax
    bool is_conn_upper_valid;     // 주기 안에 UE 축출이 있으면 false — 최댓값이 실제보다 작아 두 키를 null 로
    double conn_mean;             // 탐지 명세는 실수 가능
    uint32_t conn_max;            // 정수. 탐지 상태표의 유령 정리 기준
    bool has_inactive_si;         // RRC.InactiveConnMean·Max. 지금은 false → null
    bool is_inactive_upper_valid; // 위 is_conn_upper_valid 와 같음
    double inactive_mean;
    uint32_t inactive_max;

    // ext
    bool has_ue_ctx_max;
    uint32_t ue_ctx_max; // 칸 안 UE 컨텍스트 수 최댓값(칸 시작 때 수 포함). 탐지 경보 심각도
    bool has_du_cannot_serve;
    uint32_t du_cannot_serve; // INITIAL UL 에 DU to CU 컨테이너 없음
    bool has_crnti_alloc;
    uint32_t crnti_alloc; // INITIAL UL 수
};

#endif /* TELEMETRY_REPORT_H */
