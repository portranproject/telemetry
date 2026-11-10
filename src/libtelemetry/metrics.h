/**
 * metrics.h
 * : 표 I 과 표 II 지표 정의의 유일 출처 - X 매크로 하나에서 네 가지가 파생됨
 *
 * [1] 무엇이 파생되나. 숫자 리터럴을 따로 적는 위치가 없어 드리프트가 구조적으로 불가능함.
 *
 *     TR_METRIC_LIST(X) --+--> tr.h   enum tr_metric
 *                         +--> tr.c   지표 이름표
 *                         +--> tr.c   원인 이름표
 *                         +--> tr.c   원인 개수, CC 와 SI 구분
 *
 * [2] 지표를 넣거나 바꿀 위치는 이 파일 하나임. 지표 이름이나 원인 칸 수를 다른 파일에도 적으면
 *     한쪽만 고쳤을 때 열거형과 이름표의 길이가 어긋나는데, 둘 다 컴파일되므로 빌드가 잡지 못함.
 *
 * 근거: TS 28.552(지표 이름, §4.1a 하위카운터 철자), TS 38.331 EstablishmentCause / ResumeCause,
 *   TS 38.413 §9.3.1.111 RRCEstablishmentCause(고정 문법 15.8.0 은 11칸).
 */
#ifndef TELEMETRY_METRICS_H
#define TELEMETRY_METRICS_H

/* 원인 이름표: 태그(Y)로 확장. 순서 = ASN.1 열거 순(= 칸 번호).
 *
 * 철자는 3GPP ASN.1 값 이름 하나임. 이 문자열이 두 위치로 그대로 나감.
 *
 *     주기 보고의 원인별 카운터 하위 키    cc.RRC.ConnEstabAtt 안의 "mo-Signalling"
 *     단말 줄의 수립 원인                  f.est_cause 의 "mo-Signalling"
 *
 * 하이픈을 뺀 철자를 따로 두지 않는 이유: 그 철자는 TS 28.552 §4.1a 가 하위카운터 이름에
 *   하이픈을 금지해 필요했던 것인데, 우리가 내보내는 것은 28.552 보고가 아니라 탐지 엔진이
 *   읽는 줄이고 그 줄은 ASN.1 철자를 그대로 비교함. 철자를 두 벌 두면 반드시 어긋남.
 *
 * 철자 출처: 고정 문법 `asn1/nr-rrc-17.3.0.asn1:1397`(EstablishmentCause),
 *   `:9578`(ResumeCause), `asn1/ngap-15.8.0.asn1:5520`(RRCEstablishmentCause).
 *   기억이 아니라 문법에서 뽑음 */
#define TR_CAUSE_EST16(Y) /* TS 38.331 EstablishmentCause */ \
	Y("emergency") Y("highPriorityAccess") \
	Y("mt-Access") Y("mo-Signalling") Y("mo-Data") \
	Y("mo-VoiceCall") Y("mo-VideoCall") Y("mo-SMS") \
	Y("mps-PriorityAccess") Y("mcs-PriorityAccess") \
	Y("spare6") Y("spare5") Y("spare4") \
	Y("spare3") Y("spare2") Y("spare1")
/* 칸 수는 고정한 문법(asn1/ngap-15.8.0.asn1)의 값 개수와 같아야 함. 그 문법의
 * RRCEstablishmentCause 는 0~10 열한 개이고 notAvailable 이 유일한 확장값임.
 * mo-ExceptionData 는 Release 16 추가라 이 문법으로는 관측 자체가 불가하므로 칸을 두지 않음 -
 * 두면 늘 0 인 칸이 생겨 소비자가 "재어 봤고 0" 으로 읽음(실제 뜻은 "못 봄"). 문법을 올릴 때 같이 늘릴 것 */
#define TR_CAUSE_UEC11(Y) /* TS 38.413 §9.3.1.111 RRCEstablishmentCause */ \
	Y("emergency") Y("highPriorityAccess") \
	Y("mt-Access") Y("mo-Signalling") Y("mo-Data") \
	Y("mo-VoiceCall") Y("mo-VideoCall") Y("mo-SMS") \
	Y("mps-PriorityAccess") Y("mcs-PriorityAccess") \
	Y("notAvailable")
#define TR_CAUSE_RES16(Y) /* TS 38.331 ResumeCause */ \
	Y("emergency") Y("highPriorityAccess") \
	Y("mt-Access") Y("mo-Signalling") Y("mo-Data") \
	Y("mo-VoiceCall") Y("mo-VideoCall") Y("mo-SMS") \
	Y("rna-Update") Y("mps-PriorityAccess") \
	Y("mcs-PriorityAccess") Y("spare1") Y("spare2") \
	Y("spare3") Y("spare4") Y("spare5")
/* 칸 이름은 고정한 문법(asn1/nr-rrc-17.3.0.asn1:9578)의 값 이름을 그대로 씀 - 그 문법의
 * ResumeCause 는 순번 11, 12 가 spare1, spare2 임. Release 18 이 그 자리를 mt-SDT 와
 * srs-PosConfigOrActivationReq 로 채웠으나 우리 디코더는 17.3.0 문법이라 그 뜻을 관측할 수 없음.
 * Release 18 이름을 적으면 소비자가 "재어 봤고 0" 으로 읽지만 실제 뜻은 "못 봄" 임 -
 * 형제 TR_CAUSE_UEC11 이 mo-ExceptionData 칸을 두지 않은 것과 같은 규약임 */
// FailCause 는 ASN.1 열거가 아니라 탐지 엔진으로 나가는 점 표기 이름임
#define TR_CAUSE_FAIL3(Y) /* 수립 실패 원인 */ \
	Y("NetworkReject") Y("NoReply") Y("Other")
#define TR_CAUSE_NONE1(Y)  // 원인 분할 없음(1칸, 하위이름 "")

// 원인표 태그에서 배열 심볼로. tr.c 가 배열을 정의하고 이 매핑으로 연결함
#define TR_CAUSE_TABLE_ARR_EST16 TR_CAUSE_ARR_EST16
#define TR_CAUSE_TABLE_ARR_UEC11 TR_CAUSE_ARR_UEC11
#define TR_CAUSE_TABLE_ARR_RES16 TR_CAUSE_ARR_RES16
#define TR_CAUSE_TABLE_ARR_FAIL3 TR_CAUSE_ARR_FAIL3
#define TR_CAUSE_TABLE_ARR_NONE1 ((const char *const *)0)
/* 원인 개수는 이름표 길이에서 자동 유도함. 숫자 리터럴을 따로 적지 않으므로 드리프트가 불가능함.
 * NONE1 은 원인 분할이 없어 1칸(하위이름 "") */
#define TR_CAUSE_TABLE_COUNT1_(name) +1
#define TR_CAUSE_TABLE_COUNT_EST16 (0 TR_CAUSE_EST16(TR_CAUSE_TABLE_COUNT1_))
#define TR_CAUSE_TABLE_COUNT_UEC11 (0 TR_CAUSE_UEC11(TR_CAUSE_TABLE_COUNT1_))
#define TR_CAUSE_TABLE_COUNT_RES16 (0 TR_CAUSE_RES16(TR_CAUSE_TABLE_COUNT1_))
#define TR_CAUSE_TABLE_COUNT_FAIL3 (0 TR_CAUSE_FAIL3(TR_CAUSE_TABLE_COUNT1_))
#define TR_CAUSE_TABLE_COUNT_NONE1 1

// 종류: CC = 누적 카운터, SI = 표본 지표
#define TR_KIND_CC 0
#define TR_KIND_SI 1

/* 지표 목록: X(enum 이름, "28.552 측정 이름", 종류, 원인표 태그).
 * [INACTIVE] 는 RRC_INACTIVE 상태를 다루는 지표임 - 그 상태를 지원하지 않는 망에서는 늘 0 임 */
#define TR_METRIC_LIST(X) \
	X(TR_METRIC_RRC_CONN_ESTAB_ATT,        "RRC.ConnEstabAtt",             CC, EST16) \
	X(TR_METRIC_RRC_CONN_ESTAB_SUCC,       "RRC.ConnEstabSucc",            CC, EST16) \
	X(TR_METRIC_RRC_CONN_ESTAB_FAIL_CAUSE, "RRC.ConnEstabFailCause",       CC, FAIL3) \
	X(TR_METRIC_RRC_REL_WITHOUT_SUSPEND,   "RRC.RelWithoutSuspendConfig",  CC, NONE1) \
	X(TR_METRIC_UECNTX_CONN_ESTAB_ATT,     "UECNTX.ConnEstabAtt",          CC, UEC11) \
	X(TR_METRIC_UECNTX_CONN_ESTAB_SUCC,    "UECNTX.ConnEstabSucc",         CC, UEC11) \
	X(TR_METRIC_RRC_REESTAB_ATT,           "RRC.ReEstabAtt",               CC, NONE1) \
	X(TR_METRIC_RRC_REESTAB_SUCC_WITH_CTX, "RRC.ReEstabSuccWithUeContext", CC, NONE1) \
	X(TR_METRIC_RRC_RESUME_ATT,            "RRC.ResumeAtt",                CC, RES16) /* [INACTIVE] */ \
	X(TR_METRIC_RRC_RESUME_SUCC,           "RRC.ResumeSucc",               CC, RES16) /* [INACTIVE] */ \
	X(TR_METRIC_RRC_CONN_MEAN,             "RRC.ConnMean",                 SI, NONE1) \
	X(TR_METRIC_RRC_CONN_MAX,              "RRC.ConnMax",                  SI, NONE1) \
	X(TR_METRIC_RRC_INACTIVE_CONN_MEAN,    "RRC.InactiveConnMean",         SI, NONE1) /* [INACTIVE] */ \
	X(TR_METRIC_RRC_INACTIVE_CONN_MAX,     "RRC.InactiveConnMax",          SI, NONE1) /* [INACTIVE] */

/* 이 헤더는 매크로 전용(선언 0개)이라 단독 -pedantic 컴파일에서 '빈 번역단위' 경고가 남.
 * 실제 빌드에는 영향이 없지만 헤더 자가체크 잡음을 없애려 무해한 선언 하나를 둠 */
typedef int telemetry_metrics_header_guard_t;

#endif /* TELEMETRY_METRICS_H */
