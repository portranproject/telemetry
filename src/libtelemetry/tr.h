/**
 * tr.h
 * : libtelemetry 공개 계약 - 관측 이벤트를 받아 출력 층이 보낼 값(common/report.h)을 채움
 *
 * [1] 이 계층이 하는 일과 하지 않는 일.
 *
 *     함     TS 28.552 의 카운팅 규칙 전부. 원인별 누적 카운터, 제외 규칙(진행 중 수립,
 *            AMF 과부하), 무응답 판정, 표본 평균과 최대, 보고 주기, 늦은 이벤트,
 *            RRC_INACTIVE 를 쓰지 않는다는 전제를 깨는 증거의 경보
 *     안 함  패킷, IE, ASN.1 을 모름. 아는 것은 관측 이벤트뿐임. 그래서 단위 시험이
 *            합성 이벤트만으로 돎. JSON 과 소켓과 철자표도 모름 - 그쪽은 출력 층 담당임
 *
 * [2] 세 가지 출력. 셋 다 common/report.h 의 구조체이고, 출력 층이 그대로 줄로 만듦.
 *
 *     report_period     주기가 닫힐 때, 셀마다 한 번. 셀 카운터와 표본 지표
 *     report_ue_event   단말 관련 메시지를 볼 때마다 한 줄
 *     report_f1_event   F1 Setup 과 Reset 을 볼 때 한 줄
 *
 * [3] 부르는 순서. 시간을 먼저 진행해야 함.
 *
 *     tr_new() -> [ tr_advance(t) -> tr_on_event(event) ] 반복 -> tr_finish() -> tr_free()
 *
 *     거꾸로 두면 늦게 온 이벤트가 이미 닫힌 주기에 들어가거나, 마감이 지난 시도가 성공으로 뒤집힘.
 *
 * [4] 출력값의 등급. 내보내는 것은 본 것과 추론한 것의 합이고, 모르는 것은 섞지 않음.
 *
 *     report_counter.total = 본 것 + 추론한 것
 *     tr_stats 의 미상과 제외   따로 셈. total 에 넣지 않음
 *
 *     모르는 것을 0 으로 섞으면 "세어서 0" 과 "못 봐서 0" 이 같은 모양이 됨. 우리는 참여자가
 *     아니라 수동 관측자라 다시 달라고 할 수 없으므로, 못 읽은 것을 못 읽었다고 남기는 것 자체가
 *     기능임. 출력 규약에 그 값을 받는 칸이 없어서 tr_get_stats 로 꺼내 종료 보고에 적음.
 *
 * [5] 소유권. tr_new 가 만든 tr 은 tr_free 가 품음. 출력 레코드는 출력 콜백 안에서만 유효함.
 *
 * [6] 스레드 하나. 같은 tr 을 여러 스레드에서 부르지 않음.
 */
#ifndef TELEMETRY_TR_H
#define TELEMETRY_TR_H

#include <common/report.h>   /* 출력 층에 넘기는 값의 계약. 이 계층이 채우는 세 구조체가 여기 있음 */
#include <common/types.h>
#include "metrics.h"         /* 지표 열거형, 이름, 원인표의 유일 출처(X 매크로) */

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
/* 지표와 원인 칸의 이름. 와이어 키는 출력 층이 자기 칸 이름으로 적으므로 이 이름들은 경고 문구와
 * 원인별 카운터의 하위 키에만 씀. 원인 이름 철자는 ASN.1 값 이름임("mo-Signalling") */
const char *tr_metric_name(enum tr_metric metric);
const char *tr_cause_name(enum tr_metric metric, int cause_index);   // 범위 밖 NULL, 원인 분할이 없으면 ""
int         tr_cause_count(enum tr_metric metric);                   // 원인 칸 수(원인 분할이 없으면 1)
int         tr_metric_is_si(enum tr_metric metric);                  // 누적 카운터(0) / 표본 지표(1). 소비자가 이 구분을 다시 적지 말 것

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
	uint32_t noreply_timeout_ms;    /* 무응답 대기(0 = TR_DEF_NOREPLY_TIMEOUT_MS = 1000). 셀마다 다르게 두지 않음 -
	                                 * 광고는 한 번뿐이라 셀별 값을 내보낼 칸이 없음 */
	bool     self_check;            /* 자기 불변식 검사. true 면 게이지, 멤버십, 열린 목록의 정합을 매 이벤트와
	                                 * 주기 마감과 종료에 보고 위반 시 abort(시험과 새니타이저용). 기본 false 가
	                                 * 프로덕션임(오버헤드 때문이고 동작 차이는 없음). 환경변수 TR_SELF_CHECK 로도 켜짐 */
};

// ---- 카운팅 규칙이 제외하는 이유 ----
/* 제외는 "관측했지만 TS 28.552 의 카운팅 규칙이 그 사건을 시도로 세지 말라고 한 경우" 임.
 * 미상(그 사건을 보기는 했으나 값을 본값에 넣을 근거가 없는 경우)과 다름 - 둘을 한 칸에 합치면
 * "규칙이 뺀 것" 과 "우리가 못 읽은 것" 이 같은 모양이 되어 관측 구멍을 되짚을 수 없음 */
enum tr_excl_reason {
	TR_EXCLUDED_ONGOING_SETUP = 0,   /* 마감 안에 같은 단말이 다시 요청함(중복 시도) */
	TR_EXCLUDED_AMF_OVERLOAD,        /* AMF 과부하 구간이라 그 원인은 세지 않음 */
	TR_EXCLUDED_EST_CELL_UNKNOWN,    /* 결판은 났는데 어느 셀의 시도였는지 모름 */
	/* 아래 둘은 RRCSetupComplete 를 받았지만 수립 성공으로 세지 않은 경우임. 근거는 TS 28.552
	 * §5.1.1.15.2 c) 가 "Receipt by the gNB of an RRCSetupComplete message following a RRC
	 * connection setup request" 로 수립 요청을 뒤따른 것만 세라고 한 것임.
	 * 미상 칸이 아니라 제외 칸인 이유: 우리가 못 읽은 것이 아니라 규칙이 세지 말라고 한 것임.
	 * 그래도 세는 이유: 받은 Complete 가 어느 칸에도 없으면 '그런 Complete 가 없었다' 와 같은
	 * 모양이 되어 과소보고를 되짚을 수 없음 */
	TR_EXCLUDED_FALLBACK_COMPLETE,   /* 재수립이나 재개가 폴백해 열린 수립의 Complete */
	TR_EXCLUDED_SETTLED_COMPLETE,    /* 이미 결판난 시도에 다시 온 Complete */
	TR_EXCLUDED__COUNT
};

// ---- 단말 줄을 내지 못한 이유 ----
/* 줄을 내지 않는 것만으로는 신호 없는 드롭임. 이유마다 따로 세어 종료 보고에 적음.
 * 한 칸으로 합치지 않는 이유: 아래 일곱 가지는 뜻이 서로 다름. 앞의 둘은 우리 관측의 구멍이고,
 * 셋째는 와이어에서 보지 않은 것을 보냈다고 하지 않으려는 것이며, 나머지 넷은 NAS 를 읽지 못한
 * 서로 다른 지점임. 합치면 어느 쪽인지 되짚을 수 없음 */
enum tr_ue_event_skip {
	TR_UE_EVENT_SKIP_NO_CELL = 0,        /* 셀(NR-CGI)을 몰라 줄의 필수 칸을 채울 수 없음 */
	TR_UE_EVENT_SKIP_NO_UE_KEY,          /* 단말 키(DU UE F1AP ID)를 몰라 어느 단말의 줄인지 못 적음 */
	TR_UE_EVENT_SKIP_UNKNOWN_DIRECTION,  /* 상행인지 하행인지 판정 못 함. 방향을 추측해 적지 않음 */
	TR_UE_EVENT_SKIP_SYNTHETIC_RELEASE,  /* 와이어에서 본 해제 완료가 아니라 관측자가 합성한 것 */
	TR_UE_EVENT_SKIP_NAS_NON_DELIVERED,  /* 전달되지 않은 NAS */
	TR_UE_EVENT_SKIP_NAS_REJECTED,       /* NAS 해석 실패, 또는 보안 헤더가 방향과 어긋남 */
	TR_UE_EVENT_SKIP_NAS_UNMAPPED,       /* 아는 5GMM 메시지 번호가 아님 */
	TR_UE_EVENT_SKIP_NAS_NOT_5GMM,       /* 5GSM 자리의 값. 5GMM 표로 조회하면 다른 이름이 붙음 */
	TR_UE_EVENT_SKIP__COUNT
};

// ---- 관측 품질. 출력 규약에 받는 칸이 없어 종료 보고로만 나감 ----
/* 왜 이 구조체가 있나: 출력 규약(common/report.h)은 셀 카운터와 표본 지표를 받는 칸만 두고,
 *   "우리가 무엇을 못 봤는지" 를 받는 칸을 두지 않았음. 그 값을 버리면 못 본 구간과 조용한 구간이
 *   같은 모양이 되어 읽는 쪽이 가릴 수 없음. 그래서 여기 모아 두고 종료 보고에 찍음.
 * 값은 전부 세션 누적임(주기 델타가 아님). 주기마다 내보낼 칸이 없으므로 누적 하나로 충분함 */
struct tr_stats {
	/* 캡처와 전송 계층이 놓친 양. 이름에 접미사를 안 붙이는 이유: 같은 값이 cap_stats 에서
	 * tr_set_coverage 를 거쳐 이 칸까지 한 철자로 이어짐. 중간 한 계층만 바꾸면 계층 방언이 생김 */
	uint64_t tsn_gap_count, ringbuf_full_count, esp_seen_count, ip_frag_skipped_count;
	uint64_t obs_lost_count;             /* 관측자 내부 유실 = 매칭 대기열 넘침, 단말 축출,
	                                      * SCTP 방향과 연결 축출의 합. 0 이 아니면 그 구간의 지표는 하한임 */
	// tr 이 스스로 세는 값
	uint64_t late_event_count;           // 이미 닫은 주기 시각으로 온 이벤트
	uint64_t lost_evicted_count;         // 표가 꽉 차 밀어낸 레코드
	uint64_t reset_unresolved_count;     /* 일부 RESET 이 가리켰지만 우리 색인(연결, DU 번호)으로 못 닫은 단말.
	                                      * 근거: TS 38.473 §8.2.1.2.1 이 "gNB-CU UE F1AP ID IE and/or
	                                      * gNB-DU UE F1AP ID IE" 라 해서 CU 번호만 실린 항목이 올 수 있음.
	                                      * 못 닫으면 그 단말이 연결 게이지에 남아 Conn 지표가 과대계수됨 */
	/* inactive_observed_count: 이 망이 RRC_INACTIVE 를 쓴다고 확인된 건수(평문 suspendConfig, 재개
	 * 요청, NGAP 의 INACTIVE 보고). 0 이 아니면 si 의 연결 지표는 하한임 - INACTIVE 로 간 단말이
	 * 돌아오는 것을 암호 구간에서 볼 수 없어 그만큼이 연결 게이지에서 빠진 채로 남음 */
	uint64_t inactive_observed_count;
	uint64_t release_basis_observed_count, release_basis_assumed_count;   // 해제 근거를 평문으로 본 수와 추론한 수
	/* 카운터 본값에 넣지 않은 관측 사건. 색인은 enum tr_metric 순임.
	 *   unknown_count          그 사건을 봤고 원인도 아는데 본값에 넣을 근거가 없었음
	 *   unknown_nocause_count  그 사건을 봤는데 원인을 못 읽었음
	 * 둘을 가르는 이유: 앞은 원인별 분해가 가능한 구멍이고 뒤는 분해조차 안 되는 구멍임 */
	uint64_t unknown_count[TR_METRIC__COUNT];
	uint64_t unknown_nocause_count[TR_METRIC__COUNT];
	/* value_count: 본값으로 센 수의 세션 누적. 주기 줄에 값으로 못 싣는 지표(재수립 둘, 재개 둘)가
	 * 있어서 그 수가 여기에만 남음. 색인이 unknown_count 와 같아 한 지표의 세 밴드를 나란히 읽음 */
	uint64_t value_count[TR_METRIC__COUNT];
	uint64_t excluded_count[TR_EXCLUDED__COUNT];              // 카운팅 규칙이 제외한 수(이유별)
	/* 길이가 period_ms 가 안 돼 내보내지 못한 주기 수. 두 경우임 - 기동 시각이 주기 경계가 아니라
	 * 앞부분을 못 본 첫 주기, 그리고 관측이 주기 중간에 끝난 마지막 주기.
	 * 내보내지 않는 이유: 주기 줄은 길이가 늘 period_ms 라고 약속돼 있어, 앞뒤를 못 본 칸을 같은
	 * 길이로 내보내면 그 수가 그 칸의 전량으로 읽혀 과소보고가 됨.
	 * 그 주기의 단말 줄은 이미 나갔고 빠지는 것은 셀 카운터 기여분뿐임 */
	uint64_t unreported_period_count;
	// 출력 층에 넘기지 못한 줄
	uint64_t ue_event_skipped_count[TR_UE_EVENT_SKIP__COUNT];
	uint64_t ue_event_direction_disagree_count;   /* 관측 층이 알려 준 방향과 그 메시지가 규격상 가질 수
	                                               * 있는 방향이 다른 건수. 줄은 규격 쪽 방향으로 내보냄 */
	uint64_t f1_event_cells_unknown_count;        // 그 DU 의 셀 목록을 몰라 '모든 셀' 로 낸 F1 줄
	uint64_t f1_event_du_ue_id_missing_count;     // DU 번호가 없어 F1 줄의 단말 목록에서 뺀 항목
	/* cell_number_collision_count: 셀 번호로 NR Cell Identity 를 쓰기 때문에, PLMN 이 다른 두 셀이
	 * 같은 번호로 보인 건수. 내부 셀 표는 (PLMN, NR Cell Identity) 전체를 키로 쓰므로 집계는 갈려
	 * 있고, 합쳐져 보이는 것은 내보내는 번호뿐임. 0 이 아니면 그 구간의 셀별 줄을 믿을 수 없음 */
	uint64_t cell_number_collision_count;
	/* nas_msg_type_inferred_count: 메시지 종류를 와이어에서 읽지 못하고 보안 헤더 종류와 방향으로
	 * 추론해 낸 단말 줄 수. 줄에는 추론임을 적을 칸이 없으므로 그 사실이 이 수에만 남음 */
	uint64_t nas_msg_type_inferred_count;
	/* 해석 자체가 실패해 어느 줄에도 들어가지 못한 수. 관측 구멍이지 상대가 안 보낸 것이 아님 */
	uint64_t rrc_malformed_count, ap_decode_fail_count;
};

// ---- 출력 콜백 표 ----
/* 출력 대상이 채우는 함수 표. 이 계층은 어느 출력 모듈이 끼워졌는지 모름 - 표를 여기 두면 출력
 * 쪽이 바뀌어도 집계 코드가 다시 빌드되지 않고, 시험은 같은 표에 메모리 수집기를 끼워 씀.
 * 콜백에 넘기는 구조체와 그것이 가리키는 목록은 콜백이 돌아올 때까지만 유효함 */
struct tr_sink_ops {
	void (*on_period)(void *user_ctx, const struct report_period *period);      // 주기가 닫힐 때, 셀마다
	void (*on_ue_event)(void *user_ctx, const struct report_ue_event *event);   // 단말 관련 메시지마다
	void (*on_f1_event)(void *user_ctx, const struct report_f1_event *event);   // F1 Setup 과 Reset
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

/* 파이프라인이 누적 캡처와 SCTP 유실 카운터를 넣어 주면 tr_stats 의 같은 이름 칸에 실림
 * (관측 맹점 신호). 넣지 않으면 0. 값은 누적이고 탭 전역임 - 드롭된 패킷에는 NR CGI 가 없어
 * 셀에 귀속할 수 없으므로 셀별로 나누지 않음. */
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

/* tr_get_stats: 관측 품질 누적값을 빌려 줌. 출력 규약에 이 값을 받는 칸이 없어 호출자가 종료
 *   보고에 적는 것이 유일한 소비 경로임. 반환한 포인터는 tr 이 품으므로 tr_free 전까지만 유효함.
 *   tr 이 NULL 이면 NULL */
const struct tr_stats *tr_get_stats(const struct tr *tr);
#endif /* TELEMETRY_TR_H */
