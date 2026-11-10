/**
 * tr.h
 * : libtelemetry 공개 계약 - 관측 이벤트를 받아 주기마다 표 II(셀 카운터)와 표 I(단말 줄)을 냄
 *
 * [1] 이 계층이 하는 일과 하지 않는 일.
 *
 *     한다     TS 28.552 의 카운팅 규칙 전부. 원인별 누적 카운터, 제외 규칙(진행 중 수립,
 *              AMF 과부하), 무응답 판정, 표본 평균과 최대, 보고 주기, 늦은 이벤트,
 *              RRC_INACTIVE 를 쓰지 않는다는 전제를 깨는 증거의 경보
 *     안 한다  패킷, IE, ASN.1 을 모름 - 아는 것은 관측 이벤트뿐임. 그래서 단위 시험이
 *              합성 이벤트만으로 돎
 *
 * [2] 부르는 순서. 시간을 먼저 진행해야 함.
 *
 *     tr_new() -> [ tr_advance(t) -> tr_on_event(event) ] 반복 -> tr_finish() -> tr_free()
 *
 *     거꾸로 두면 늦게 온 이벤트가 이미 닫힌 주기에 들어가거나, 마감이 지난 시도가 성공으로 뒤집힘.
 *
 * [3] 출력값의 등급. 내보내는 것은 본 것과 추론한 것의 합이고, 모르는 것은 섞지 않음.
 *
 *     value = exact + inferred      <- TS 28.552 카운터 값
 *     unknown, excluded             <- 따로 셈. value 에 넣지 않음
 *
 *     모르는 것을 0 으로 섞으면 "세어서 0" 과 "못 봐서 0" 이 같은 모양이 됨.
 *
 * [4] 소유권. tr_new 가 만든 tr 은 tr_free 가 품음. 출력 레코드는 출력 콜백 안에서만 유효함.
 *
 * [5] 스레드 하나. 같은 tr 을 여러 스레드에서 부르지 않음.
 */
#ifndef TELEMETRY_TR_H
#define TELEMETRY_TR_H

#include <common/types.h>
#include "metrics.h"   /* 지표 열거형, 이름, 원인표의 유일 출처(X 매크로) */

// ---- 표 II 지표 14종 ----

/* 단말의 NAS 상태 - AMF 쪽 5GMM 주 상태(TS 24.501 §5.1.3.2.3)와 연결 모드의 값 코드북.
 * 숫자를 직접 적지 말 것 */
enum tr_5gmm_state {
	TR_5GMM_UNKNOWN = 0,        /* 판정 불가(늦게 합류, 암호 뒤) */
	TR_5GMM_DEREGISTERED,       /* 컨텍스트 없음, 해제 */
	TR_5GMM_COMMON_PROC_INIT,   /* 공통 절차 응답 대기 */
	TR_5GMM_REGISTERED,         /* 컨텍스트 있음 */
	TR_5GMM_DEREG_INITIATED     /* 망 발신 해제 응답 대기 */
};
enum tr_cm_mode { TR_CM_MODE_UNKNOWN = 0, TR_CM_MODE_IDLE, TR_CM_MODE_CONNECTED };   // 연결 모드

// enum tr_metric 은 metrics.h 의 TR_METRIC_LIST 에서 파생됨. 추가와 변경은 그 파일에서 함
enum tr_metric {
#define X(id, name, kind, ct) id,
	TR_METRIC_LIST(X)
#undef X
	TR_METRIC__COUNT
};
/* TS 28.552 측정 이름("RRC.ConnEstabAtt"). 원인 하위 이름에는 영숫자만 쓸 수 있어
 * (TS 28.552 §4.1a) tr_cause_subname 이 하이픈을 뺌. ASN.1 철자를 그대로 쓰는 쪽은
 * tr_cause_asn1_name 이고, 탐지 엔진으로 나가는 줄만 그것을 씀 */
const char *tr_metric_name(enum tr_metric metric);
const char *tr_cause_subname(enum tr_metric metric, int cause_index);   // 예: mo-Signalling -> "moSignalling". 범위 밖 NULL
const char *tr_cause_asn1_name(enum tr_metric metric, int cause_index); // 같은 칸의 ASN.1 값 이름("mo-Signalling"). 범위 밖 NULL
int         tr_cause_count(enum tr_metric metric);                      // 원인 칸 수(원인 분할이 없으면 1)
int         tr_metric_is_si(enum tr_metric metric);                     // 누적 카운터(0) / 표본 지표(1). 소비자가 이 구분을 다시 적지 말 것

/* TR_DEF_NOREPLY_TIMEOUT_MS: 무응답 대기(ms). 구간은 RRCSetup(Msg4)을 본 시각부터
 *   RRCSetupComplete(Msg5)가 올 때까지이고, 재는 쪽은 CU 임.
 *   공개하는 이유: 출력 쪽이 이 값을 그대로 광고해야 함. 그 값을 받는 탐지 엔진은 시도 창을
 *     ceil(timeout/period) 칸 뒤로 밀어 무응답과 매칭하므로, 광고값과 실제 임계가 다르면
 *     매칭이 어긋나고 1단계 판정이 조용히 틀림.
 *   값 1000 의 근거: TS 28.552 §5.1.1.15.3 c) 는 "the expected RRCSetupComplete message was not
 *     received by the gNB from UE after the RRCSetup message (see TS 38.331 [20])" 로 구간만 정하고
 *     숫자는 다른 조항으로 넘김. 그래서 숫자는 값을 받는 쪽과 맞춘 1000 을 쓰고, 그쪽이 적은
 *     구간이 우리 구간과 같은지 확인한 뒤 씀.
 *   셀 SIB1 의 T300 을 쓰지 않는 이유: T300 은 단말이 RRCSetupRequest(Msg3)를 보낼 때 시작해
 *     Msg4 를 받으면 멈추는 타이머라(TS 38.331 §7.1.1 표) 재는 쪽도 구간도 다름. 또한 셀마다
 *     다를 수 있는 값을 광고 한 번으로 내보내면 그 셀부터 광고값과 실제 임계가 어긋남. */
#define TR_DEF_NOREPLY_TIMEOUT_MS 1000u

/* TR_DEF_SETUP_OUTCOME_TIMEOUT_MS: RRCSetupRequest(Msg3)만 보고 결과를 못 본 수립을 포기하는 시각(ms).
 *   위 값과 다른 구간임. 한 값으로 묶으면 안 되는 이유가 아래 표임.
 *
 *                      누가 재나          어디서 시작       어디서 멈춤        마감이 내는 것
 *     무응답           CU(우리가 관측)    Msg4 송신         Msg5 도착          FailCause[NoReply]
 *     수립 결과 미관측 우리(관측자)       Msg3 관측         Msg4 또는 Msg5     cc_unknown_nocause
 *
 *   값 2000 의 근거: 이 구간은 단말의 T300 과 끝점이 같음(Msg3 송신 ~ Msg4 수신, TS 38.331 §7.1.1 표).
 *     T300 이 끝나면 단말이 수립을 포기하므로 그 뒤로는 Msg4 도 Msg5 도 올 수 없음. 우리는 셀의
 *     T300 설정을 모르지만(SIB1 은 F1 에 실리지 않음) 상한은 규격이 정해 두었음 -
 *     `t300 ENUMERATED {ms100, ms200, ms300, ms400, ms600, ms1000, ms1500, ms2000}`(TS 38.331 §6.3.2).
 *     최대값 2000 을 쓰면 어떤 셀 설정에서도 단말이 아직 기다리는 동안 우리가 먼저 포기하지 않음.
 *   1000 을 같이 쓰면 안 되는 이유(실측): Msg3 에서 Msg4 까지 1000 ms 를 넘긴 수립이 성공으로 안
 *     잡히고 cc_unknown_nocause 로 들어감. 과부하에서 CU 의 Msg4 가 늦는 것이 이 제품의 표적 상황임.
 *   광고하지 않는 이유: 이 값을 받는 칸이 출력 규약에 없음. 받는 쪽은 무응답만 매칭함. */
#define TR_DEF_SETUP_OUTCOME_TIMEOUT_MS 2000u

/* TR_DEF_LATE_SLACK_MS: 레코드가 없는 동안 시간을 진행시킬 때 현재 시각에서 물려 둘 여유(ms).
 *   이유: 링 버퍼에서 늦게 올라오는 레코드가 이미 닫은 주기에 떨어지면 late_event_count 로 샘.
 *   공개하는 이유: 유휴 진행은 호출자가 하므로 그쪽이 이 값을 알아야 함. 종전에는
 *     tr_cfg.late_slack_ms 가 선언만 돼 있고 읽는 곳이 하나도 없었음. */
#define TR_DEF_LATE_SLACK_MS 50u

/* 보고 주기 기본값. 공개하는 이유: gp_ms 가 0(기본) 일 때 다른 모듈도 같은 값을 알아야 함 -
 *   출력 쪽이 광고하는 주기는 첫 주기보다 먼저 나갈 수 있어 그 위치에서 결정해야 하고, 종전엔
 *   0 을 받아 `gp ? gp : 1` 로 1 ms 를 지어냈음(실제 주기는 900000 ms. 조용한 오값이었음).
 *   소비자가 숫자를 다시 적으면 드리프트가 생기므로 여기 하나만 둠. TS 32.401 §5.4.1.4. */
#define TR_DEF_GP_MS 900000u

// ---- 설정. 0 으로 둔 칸은 괄호 안 기본값으로 대체함 ----
struct tr_cfg {
	uint64_t gp_ms;                 /* 보고 주기(0 = TR_DEF_GP_MS = 900000 = 15분, TS 32.401 §5.4.1.4.
	                                 * 준실시간은 임의 ms = E2SM-KPM Granularity Period) */
	uint64_t gp_origin_ns;          /* 주기 원점(0 = 벽시계 gp 배수). 두 실행의 주기 경계를 맞춰
	                                 * 산출물을 대조할 때 씀 */
	uint32_t conn_sample_period_ms;        // ConnMean 과 ConnMax 의 표본 간격 (100)
	uint32_t inactive_sample_period_ms;    // Inactive 표본 간격 (100 - TS 38.314 §4.2.1.4 상한)
	uint32_t setup_outcome_timeout_ms;  /* Msg3 만 보고 결과를 못 본 수립을 포기하는 시각
	                                     * (0 = TR_DEF_SETUP_OUTCOME_TIMEOUT_MS = 2000). 위 상수의 구간 표를 볼 것 */
	uint32_t noreply_timeout_ms;    /* 무응답 대기(0 = TR_DEF_NOREPLY_TIMEOUT_MS = 1000). 셀마다 다르게 두지 않음 -
	                                 * 광고는 한 번뿐이라 셀별 값을 내보낼 칸이 없음 */
	uint32_t late_slack_ms;         /* 유휴 진행 워터마크 여유(0 = TR_DEF_LATE_SLACK_MS = 50).
	                                 * tr 이 아니라 호출자가 읽음 - 시간을 진행시키는 쪽이 그쪽임 */
	uint32_t max_cell_count;        // 셀 표 상한 (4096). 넘으면 '넘침 셀' 하나에 모으고 경고를 냄
	bool     assume_no_inactive;    /* 망이 RRC_INACTIVE 를 쓰지 않는다는 전제. 모든 보고 헤더에 기록하고,
	                                 * 그 전제를 깨는 증거가 보이면 경보를 올림 */
	bool     self_check;            /* 자기 불변식 검사. true 면 게이지, 멤버십, 열린 목록의 정합을 매 이벤트와
	                                 * 주기 마감과 종료에 보고 위반 시 abort(시험과 새니타이저용). 기본 false 가
	                                 * 프로덕션임(오버헤드 때문이고 동작 차이는 없음). 환경변수 TR_SELF_CHECK 로도 켜짐 */
};

// ---- 출력 레코드 ----
enum tr_excl_reason {
	TR_EXCLUDED_ONGOING_SETUP = 0, TR_EXCLUDED_AMF_OVERLOAD, TR_EXCLUDED_EST_CELL_UNKNOWN,
	TR_EXCLUDED__COUNT
};
enum tr_overlap { TR_OVERLAP_ONGOING_AND_OVL_EXCL = 0, TR_OVERLAP_ONGOING_AND_OVL_UNKNOWN, TR_OVERLAP__COUNT };
/* PATH_LATE_COMPLETE 를 PATH_OTHER 와 가르는 이유: 둘 다 '본값이 아닌 Complete' 지만 검산에서
 *   뜻이 반대임.
 *     늦은 Complete   마감 때 무응답으로 결판난 시도가 두 번째로 결판남
 *                     -> 받는 쪽의 검산식 Att - Succ - Fail 에서 빼 줘야 함
 *     중복 Complete   이미 성공으로 닫힌 시도의 군더더기 -> 뺄 것이 없음
 *   한 칸에 합치면 두 수를 분리할 수 없음 */
enum tr_path { PATH_SETUP = 0, PATH_REEST_FALLBACK, PATH_RESUME_FALLBACK, PATH_LATE_COMPLETE, PATH_OTHER, PATH__COUNT };

/* 누적 카운터의 원인 칸 하나: value = exact + inferred. unknown 과 excluded 는 value 에 넣지 않음.
 * 검산: 칸마다 (value + unknown + excluded 합) 을 더하고 cc_unknown_nocause 를 더하면 관측 사건 수가 됨.
 * overlap 은 이 합에 넣지 않음 */
struct tr_cc_cell {
	uint32_t value, exact, inferred, unknown;
	uint32_t excluded[TR_EXCLUDED__COUNT];
	uint32_t overlap[TR_OVERLAP__COUNT];
};

// 표본 지표 하나: lower <= value <= upper. upper 는 관측된 모집단을 기준으로 한 상한임
struct tr_si {
	double   value, lower, upper;          // TS 28.552 Mean 은 실수. Max 는 정수 값을 double 에 담음
	int64_t  floor_value;                  // TS 38.314 식의 내림 정수(보조 칸)
	uint64_t si_sum[3];                    // 수준별 누적 (lower, value, upper 순)
	uint32_t sample_count;                 /* 이 주기에 게이지를 친 표본 수. 0 이면 value 와 lower 와 upper 는 '값 없음'.
	                                        * 이름: 종전 `n` 은 허용목록 밖 한 글자이면서 공개 헤더 필드였고, 같은 수를
	                                        * 담는 내부 필드가 `conn_n` 과 `conn_ticks` 로 또 갈려 한 개념에 세 이름이었음.
	                                        * 셋 다 `*_sample_count` 로 통일했음 */
	bool     has_value;
	bool     upper_valid;                  // 그 주기에 축출이 있었으면 false
	bool     upper_unbounded;              // Inactive: assume_no_inactive 가 꺼져 있으면 상한 없음
};

// ---- 보고 헤더. 셀마다, 주기마다 ----
struct tr_report_header {
	struct tr_nr_cgi cell;
	uint64_t period_start_ns, period_end_ns;   // [시작, 끝)
	uint64_t gp_ms;
	bool     partial;                          // 관측 시작이나 끝이 걸친 주기
	bool     capture_alive;                    /* 이 주기 끝까지 캡처가 살아 있었음이 확인됐나.
	                                            * 거짓이면 소비자는 카운터를 0 으로 읽으면 안 됨 - 센 것이 아니라
	                                            * 안 센 것임. 0 으로 채우면 받는 쪽이 그 구간을 조용한 정상 셀로
	                                            * 보고 그동안의 공격을 놓침 */
	bool     late_join;
	bool     n2_observed;                      // 이 주기에 N2 연결을 봤는가
	bool     assume_no_inactive;
	uint32_t inactive_alarm_count;             // RRC_INACTIVE 를 쓰지 않는다는 전제를 깨는 증거를 본 수(망이 확인해 준 것만)
	uint32_t release_basis_observed_count, release_basis_assumed_count;   // 해제 근거를 평문으로 본 수와 추론한 수
	/* 이름 규칙 - 이 헤더 안에 두 군이 섞여 있고 그것이 의도임:
	 *  (1) 커버리지 군 `tsn_gap_count, ringbuf_full_count, esp_seen_count, ip_frag_skipped_count,
	 *      obs_lost_count` 는 접미사를 안 붙임. 같은 값이 cap.h 의 cap_stats 에서 tr_set_coverage 를
	 *      거쳐 이 헤더와 출력 키까지 한 철자로 이어지므로, 중간 한 계층만 바꾸면 계층 방언이 생김.
	 *  (2) tr 이 스스로 세는 카운트는 `_count` 를 붙임(late_event_count, lost_evicted_count,
	 *      inactive_alarm_count, release_basis_*_count, late_join_ul_srb1_count).
	 *  형제 비대칭은 (2) 안에서 막음 - 종전엔 `late_event_count` 는 붙고 바로 옆 `lost_evicted` 가
	 *  안 붙어 있었음(같은 줄, 둘 다 tr 의 자기 카운트). 그것이 실제 결함이었음 */
	uint64_t tsn_gap_count, ringbuf_full_count, late_event_count, lost_evicted_count;
	uint64_t esp_seen_count;                   // IPsec 감지용
	uint64_t ip_frag_skipped_count;            // IP 단편 건너뜀(이 주기 델타). 관측 맹점 신호
	uint64_t obs_lost_count;                   /* 관측자 내부 유실(이 주기 델타) = 매칭 대기열 넘침, 단말 축출,
	                                            * SCTP 방향과 연결 축출의 합. 과부하로 추적을 놓친 양이고,
	                                            * 0 이 아니면 그 창의 지표는 하한임 */
	bool     coverage_tapwide;                 /* 위 커버리지 칸들은 탭 전역 델타가 그 주기의 모든 셀 헤더에 같은
	                                            * 값으로 복제된 것임(드롭된 패킷에는 NR CGI 가 없음).
	                                            * 소비자 집계 규칙: 셀 간 최댓값이나 첫 값으로 취할 것. 셀별 합산은
	                                            * 셀 수만큼 과대가 되므로 금지. 단일 셀이면 무관 */
	uint32_t noreply_timeout_ms;               /* 이 주기에 실제로 적용한 무응답 대기(ms) = tr_cfg 값 또는
	                                            * TR_DEF_NOREPLY_TIMEOUT_MS.
	                                            * 보고하는 이유: 출력 쪽이 광고한 값과 대조해 어긋나면 알림. 둘이 다르면
	                                            * 받는 쪽이 시도 창을 잘못된 칸 수만큼 밀어 무응답과 매칭하므로 1단계
	                                            * 판정이 조용히 틀림. 지금은 세션 안에서 상수지만, 호출자가 tr 과 출력에
	                                            * 다른 값을 넘기는 배선 실수는 이 칸으로만 잡힘 */
	/* resume_none_proven: 지금은 늘 false 임(tr.c 가 상수로 넣음). 네 조건 중 넘어온 미완 재개와
	   상향이 늦게 붙은 경우를 obs 가 알려 주지 못하므로, 모르는 조건을 증명했다고 주장하지 않음.
	   즉 false 는 "재개가 있었다" 가 아니라 "증명하지 못했다" 임 - 소비자는 둘을 가를 것 */
	bool     resume_none_proven;               /* 재개 요청 0, 넘어온 미완 재개 0, 유실 0, 상향 늦게 붙음 0 이면
	                                            * 재개 지표의 0 이 구조에서 나온 것이라는 뜻 */
	/* late_join_ul_srb1_count: 지금은 늘 0 임(tr.c 가 상수로 넣음). 올리는 근거인 "UL RRC MESSAGE
	   TRANSFER 로 처음 생긴 레코드" 를 obs 가 알려 주지 못함 - obs 는 레코드를 만든 입력이 무엇이었는지
	   보존하지 않음. 같은 까닭으로 resume_none_proven 도 false 로 고정됨.
	   "재어 봤고 0" 으로 읽지 말 것(형제 alg_change_opportunity_count 와 같은 사정) */
	uint32_t late_join_ul_srb1_count;          // 이 주기에 UL RRC MESSAGE TRANSFER 로 생긴 늦게 붙은 레코드 수(탭 전체)
	uint32_t reset_unresolved_count;           /* 일부 RESET 이 가리켰지만 우리가 못 닫은 단말 수(탭 전체, 이 주기 델타).
	                                            * 왜 필요한가: TS 38.473 §8.2.1.2.1 이 "gNB-CU UE F1AP ID IE and/or
	                                            * gNB-DU UE F1AP ID IE" 라고 적어 CU 번호만 실린 항목이 올 수 있는데,
	                                            * 우리 색인은 (연결, DU 번호)뿐이라 그 단말을 가리킬 수 없음. 닫지 않으면
	                                            * 그 단말이 연결 게이지에 남아 RRC.ConnMean 과 RRC.ConnMax 가 과대계수됨.
	                                            * 못 닫았다는 사실을 안 적으면 그 과대계수를 아무도 되짚을 수 없음.
	                                            * coverage_tapwide 와 같은 집계 규칙임 - 셀 간 합산 금지 */
};

/* 표 II: 셀마다, 주기마다 한 번. cc_cells[m] 은 원인 칸 배열(tr_cause_count 개)이고,
 * 누적 카운터가 아닌 지표는 NULL */
struct tr_period_report {
	const struct tr_report_header *report_header;
	const struct tr_cc_cell *cc_cells[TR_METRIC__COUNT];
	uint32_t cc_unknown_nocause[TR_METRIC__COUNT];
	const uint32_t *path_value[TR_METRIC__COUNT];   // PATH__COUNT 개 또는 NULL(경로 하위 칸이 없는 지표)
	struct tr_si si_stats[TR_METRIC__COUNT];        // 표본 지표만 의미 있음
	struct tr_si diag_half_open;                    // 비표준 진단: 반쯤 열린 연결
	// TS 28.552 밖의 확장 3종. si_stats 와 달리 표본이 아니라 셀 상태를 바로 센 값임
	uint32_t ue_context_max;      // 주기 안 단말 컨텍스트 수의 최댓값. 주기 시작값(이월분) 포함
	uint32_t initial_ul_count;    // 주기 안 INITIAL UL RRC MESSAGE TRANSFER 건수
	uint32_t no_du_to_cu_count;   // 그중 DU to CU RRC Container 가 없던 건수(types.h 의 initial_ul 주석에 근거 인용)
};

// ---- 표 I: 값이 바뀐 이벤트마다 한 줄, 레코드가 닫힐 때 한 줄 ----
struct tr_ue_line {
	uint64_t wallclock_ns;
	enum tr_event_kind trigger_event;            // 이 줄을 만든 이벤트
	struct tr_f1ue f1ue;  struct tr_n2ue n2ue;  struct tr_nr_cgi cell;
	uint32_t changed_mask;                       // 바뀐 항목 비트(아래 TR_UE_F_*)
	bool     closed;
	/* 아래 항목은 값과 등급을 함께 냄. 값 코드북은 이렇게 읽음:
	 *   rrc_state      UNKNOWN, IDLE_PENDING, CONNECTED, INACTIVE, RELEASED
	 *   rrc_sec_state  NONE, CMD_SENT, ACTIVE, FAILED, UNKNOWN
	 *   nas_sec_state  등급을 칸마다 따로 둠 */
	uint32_t crnti;              enum tr_quality crnti_quality;
	uint64_t stmsi48;  bool has_stmsi48;        enum tr_quality stmsi48_quality;
	int      ciph_alg, integ_alg;               enum tr_quality alg_quality;          // AS Security Mode Command 가 고른 값
	int      ciph_alg_now, integ_alg_now;       // 지금 쓰는 값(처음에는 Security Mode Command 가 고른 값)
	bool     alg_changed_after_smc;
	/* alg_change_opportunity_count: 지금은 늘 0 임. 올리는 유일한 입력이 알고리즘 변경 기회 이벤트인데
	   obs 가 그것을 내지 못함 - 판단 근거인 F1AP 의 확장 IE 119(HandoverPreparationInformation)
	   유무가 ap.h 에 없음. "재어 봤고 0" 으로 읽지 말 것 */
	uint32_t alg_change_opportunity_count;
	int      rrc_state;                         enum tr_quality rrc_state_quality;
	int      nas_reg_state, nas_conn_mode;      enum tr_quality nas_state_quality;    // UNKNOWN 포함
	int      rrc_sec_state;                     enum tr_quality rrc_sec_quality;
	int      nas_sec_state;                     enum tr_quality nas_sec_quality;
	int      nas_ciph_alg;                                 // NAS 암호 알고리즘. 못 봤으면 -1
	int      rrc_chan; const char *rrc_msg_name;          enum tr_quality rrc_msg_quality;      // (통로, ASN.1 타입 이름)
	int      nas_epd, nas_sht, nas_msg_type;    enum tr_quality nas_msg_quality;      // (EPD, SHT, 타입)
};
enum {
	TR_UE_F_CRNTI = 1u << 0, TR_UE_F_STMSI = 1u << 1, TR_UE_F_ALG = 1u << 2, TR_UE_F_RRC_STATE = 1u << 3,
	TR_UE_F_NAS_STATE = 1u << 4, TR_UE_F_SEC = 1u << 5, TR_UE_F_RRC_MSG = 1u << 6, TR_UE_F_NAS_MSG = 1u << 7
};

// ---- 출력 콜백 표 ----
/* 출력 대상이 채우는 함수 표. 이 계층은 어느 출력 모듈이 끼워졌는지 모름 - 표를 여기 두면 출력
 * 쪽이 바뀌어도 집계 코드가 다시 빌드되지 않고, 시험은 같은 표에 메모리 수집기를 끼워 씀.
 * 콜백에 넘기는 레코드는 콜백이 돌아올 때까지만 유효함. */
struct tr_sink_ops {
	void (*on_period)(void *user_ctx, const struct tr_period_report *report);   // 표 II. 셀마다, 주기마다
	void (*on_ue_line)(void *user_ctx, const struct tr_ue_line *ue_line);       // 표 I. 값이 바뀔 때와 닫힐 때
	void (*on_warning)(void *user_ctx, const char *code, const char *detail);   // 넘친 셀, 이름 겹친 AMF, 경보
};

// ---- 함수 ----
struct tr;
/* sink_ops 는 복사해 둠. user_ctx 는 빌려 씀(tr 보다 오래 살아야 함).
 *   sink_ops 가 NULL 이면 보고를 전부 버림 - 계측만 돌리는 시험용. 실패하면 NULL. */
struct tr *tr_new(const struct tr_cfg *tr_cfg, const struct tr_sink_ops *sink_ops, void *user_ctx);
// 시간 먼저: 표본 반영, 마감, 주기 닫기. 시각은 줄어들지 않아야 함
void tr_advance(struct tr *tr, uint64_t now_ns);
// 그다음 이벤트. 이미 닫은 주기 시각의 이벤트는 늦은 이벤트로 처리하고 카운팅함
void tr_on_event(struct tr *tr, const struct obs_event *event);
// 입력 끝: 마지막 주기를 partial 로 닫아 냄
void tr_finish(struct tr *tr, uint64_t end_ns);
void tr_free(struct tr *tr);

/* 파이프라인이 누적 캡처와 SCTP 유실 카운터를 넣어 주면, 보고 헤더의 tsn_gap_count,
 * ringbuf_full_count, esp_seen_count, ip_frag_skipped_count 를 이 주기 델타로 채움(관측 맹점 신호).
 * 넣지 않으면 0. 값은 누적이고 탭 전역임. ringbuf_full_count 와 IP 단편은 셀에 귀속할 수 없어
 * (드롭된 패킷에는 NR CGI 가 없음) 주기마다 모든 셀 헤더에 복제함. */
void tr_set_coverage(struct tr *tr, uint64_t coverage_tsn_gap_count, uint64_t coverage_ringbuf_full_count,
                     uint64_t coverage_esp_seen_count, uint64_t coverage_ip_frag_skipped_count);
/* 관측자 내부 유실 누적(매칭 대기열 넘침, 단말과 방향과 연결 축출의 합)을 커버리지에 공급함 -
 * 주기 헤더의 obs_lost_count 델타로 실림 */
void tr_set_obs_coverage(struct tr *tr, uint64_t coverage_obs_lost_count);

/* tr_set_capture_alive: 이 시각까지 캡처가 살아 있었다고 알림(워터마크).
 *   왜 호출자가 알려 주나: 패킷이 0건인 주기는 '조용한 망' 과 '탭이 죽음' 이 같은 모양임.
 *     앞은 0 으로 세는 것이 맞고 뒤는 안 센 것이라 값이 없어야 하는데, 둘을 가르는 사실
 *     (탭이 아직 붙어 있나)은 libcap 을 쥔 호출자만 암. 라이브에서는 `cap_poll` 이 음수가 아니면
 *     그 시각까지 살아 있었다는 뜻임 - 탭이 떨어지면 1초 안에 -ENODEV 를 돌려줌.
 *   안 부르면: 모든 주기가 '확인되지 않음' 으로 나감(fail-closed). 재생처럼 입력이 구조상 완전한
 *     경우는 UINT64_MAX 를 한 번 넘기면 됨.
 *   워터마크는 단조여야 함 - 뒤로 가는 값은 무시함(한 번 확인한 과거를 되물릴 수 없음). */
void tr_set_capture_alive(struct tr *tr, uint64_t capture_alive_until_ns);
bool tr_period_pending_close(const struct tr *tr, uint64_t now_ns);   // 주기 닫힘 직전에만 커버리지를 갱신하려고 두는 관문. 라이브 오버헤드를 줄임
// 진단과 시험용: 현재 N2 레코드 수. 생명주기 누수 회귀 검사에 씀
uint32_t tr_n2_count(const struct tr *tr);
#endif /* TELEMETRY_TR_H */
