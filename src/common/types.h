/**
 * common/types.h
 * : 모듈들이 공유하는 기본 타입 - 관측 이벤트 하나
 *
 * [1] 쓰는 쪽은 하나, 읽는 쪽은 둘임.
 *
 *     libobs --struct obs_event--+--> libtelemetry   표 I/II 집계
 *                                |
 *                                +--> sink_kpm2      탐지 엔진용 ue_evt 줄
 *                                                      (와이어로 나가는 유일한 경로)
 *
 *     sink_jsonl 은 표 보고만 받고 이 구조체를 보지 않음.
 *     잎 100개 중 18개는 둘 다 읽지 않아 지금은 아무에게도 닿지 않음. 칸을 넣거나 지우기 전에
 *     그 칸을 읽는 쪽이 있는지 먼저 확인할 것.
 *
 * [2] 경계. 이 헤더는 ASN.1(asn1c) 타입을 포함하지 않음. 공유 계층이 디코더 헤더
 *     (ap.h, rrc.h, nas.h)에 매달리지 않게 하려는 것이고, 번역은 obs.c 한 곳에서만 함.
 *
 * [3] 소유권. 문자열과 바이트 포인터(예: ng_setup.amf_name)는 이벤트를 넘겨받은 콜백 안에서만
 *     유효함(빌린 메모리). 뒤에도 쓰려면 복사할 것.
 *
 * [4] 이벤트 번호는 탐지 엔진과 맞춘 값임. 바꾸거나 재사용하지 않음.
 *
 * [5] 센티널. 정수 칸의 -1 은 '안 읽음' 하나만 뜻함. 뜻이 둘이 되면 소비자가 가릴 수 없음.
 */
#ifndef TELEMETRY_TYPES_H
#define TELEMETRY_TYPES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ---- 판정 등급 ------------------------------------------------------------------- */
enum tr_quality {
	TR_QUALITY_EXACT = 0,   /* 트리거 메시지 내용이 평문으로 보임 */
	TR_QUALITY_STRUCT,      /* 같은 인터페이스의 표준 절차 흐름으로 판정 */
	TR_QUALITY_CROSS,       /* F1 과 N2 를 짝지어야 판정됨 */
	TR_QUALITY_UNKNOWN      /* 판정 불가 */
};

/* ---- 인터페이스와 방향 ----------------------------------------------------------- */
enum tr_iface { TR_IFACE_F1 = 1, TR_IFACE_N2 = 2 };

/* NAS 와 AS 보안 상태. rrc_sec_state 와 nas_sec_state 의 값 코드북임 - 숫자를 직접 적지 말 것 */
enum tr_sec_state {
	TR_SEC_NONE = 0,   /* 보안 전 */
	TR_SEC_CMD_SENT,   /* SECURITY MODE COMMAND 봄 */
	TR_SEC_ACTIVE,     /* SECURITY MODE COMPLETE / 보호된 메시지로 활성 확인 */
	TR_SEC_FAILED,     /* SECURITY MODE REJECT */
	TR_SEC_UNKNOWN     /* 판정 불가 */
};
/* F1: UP = DU→CU, DOWN = CU→DU.  N2: UP = CU→AMF, DOWN = AMF→CU
 * UNKNOWN=0 이 있어야 하는 이유: 루프백처럼 한 패킷을 두 훅이 모두 보는 장치에서는 방향을
 *   미상으로 두고 그 수를 세야 함. 또 Reset(F1AP proc_code 0)은
 *   TS 38.473 §8.2.1 상 CU 와 DU 양쪽이 개시할 수 있어 절차만으로는 방향이 안 정해짐. UNKNOWN 이
 *   없으면 그런 경우에도 UP/DOWN 중 하나를 **추측해 사실처럼 싣게 됨**(= 조용한 오값).
 *   번호를 0 으로 둔 이유: 구조체를 0 으로 초기화하면 자동으로 미상이 됨 - 채우는 것을 잊어도 거짓이 아님 */
enum tr_direction { TR_DIRECTION_UNKNOWN = 0, TR_DIRECTION_UP = 1, TR_DIRECTION_DOWN = 2 };

/* NR CGI = PLMN(3 B, TS 38.413/38.473 의 PLMN Identity 부호 그대로) + NR 셀 번호 36비트 */
struct tr_nr_cgi {
	uint8_t  plmn_bytes[3];
	uint64_t cell_id;   /* 하위 36비트만 씀 */
	bool     valid;
};

/* F1 단말 키: du_id = gNB-DU ID, 모르면 임시 키(연결 번호)와 du_id_is_temp=true */
struct tr_f1ue {
	uint64_t du_id;          /* gNB-DU ID(0..2^36-1) 또는 임시 키 */
	bool     du_id_is_temp;
	uint32_t du_ue_id;       /* gNB-DU UE F1AP ID */
	uint32_t cu_ue_id;       /* gNB-CU UE F1AP ID */
	bool     has_cu_ue_id;
	/* crnti: 그 단말의 C-RNTI. INITIAL UL RRC MESSAGE TRANSFER 에서 배워 단말 레코드가 들고 있음.
	 *   키마다 한 번 배우면 그 단말의 **모든** 이벤트에 같이 실림 - 탐지 명세가 모든 줄에 요구하고,
	 *   출력 층이 단말 표를 또 만들어 같은 값을 다시 기억하지 않게 하려는 것임. 못 배웠으면 false */
	uint32_t crnti;
	bool     has_crnti;
	bool     valid;
};

/* N2 단말 키 */
struct tr_n2ue {
	uint32_t assoc_id;
	uint64_t ran_ue_ngap_id;
	uint64_t amf_ue_ngap_id;
	bool     has_amf_ue_ngap_id;
	bool     valid;
};

/* F1AP 및 NGAP PDU 의 세 갈래. bool 하나로 줄이면 '실패' 가 '성공' 과 같은 값이 되어
 *   출력이 UEContextSetupFailure 를 UEContextSetupResponse 로 내보냄(= 조용한 오값).
 *   번호는 ap.h 의 F1AP_PDU_* 와 같은 순서지만 **별개 타입**임([2] 경계) */
enum tr_ap_outcome {
	TR_AP_OUTCOME_REQUEST = 1,   /* initiatingMessage */
	TR_AP_OUTCOME_SUCCESS,       /* successfulOutcome */
	TR_AP_OUTCOME_FAILURE        /* unsuccessfulOutcome */
};

#endif /* TELEMETRY_TYPES_H */
