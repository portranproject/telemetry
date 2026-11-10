/**
 * obs.c
 * : 관측 엔진 - SCTP 메시지에서 단말 상태를 따라가며 관측 이벤트를 냄. 카운팅은 하지 않음
 *
 * [1] 파이프라인에서의 위치.
 *
 *     libcap --패킷--> libsctp --SCTP 메시지--> [libobs] --관측 이벤트--> libtelemetry --> libsink
 *                                                  |
 *                                 libap / librrc / libnas (PDU 해석)
 *
 *     libobs 는 "무슨 일이 일어났나" 만 냄. "몇 번 일어났나" 는 libtelemetry 몫임(TS 28.552 규칙 반영).
 *     추론 규칙도 여기 두지 않음 - 이 계층은 한 메시지만 보고, 추론은 주기와 짝을 봐야 하기 때문임.
 *
 * [2] 표와 키. 이 파일 앞부분이 네 표를 만들고 찾고 지움.
 *
 *                     키                                    언제 사라지나
 *     ue_states       (SCTP 연결, gNB-DU UE F1AP ID)        RELEASE COMPLETE, 유예 만료, TTL, 축출
 *     n2_states       (SCTP 연결, RAN-UE-NGAP-ID)           같음. SCTP 연결이 AMF 를 대리함
 *     assoc_records   (SCTP 연결)                           연결 종료. gNB-DU ID 와 셀 목록을 들고 있음
 *     corr_keys       (셀, 수립 원인, NAS 길이, NAS 해시)    짝 시간창 만료
 *
 *     참조는 N2 에서 F1 한 방향뿐임. 되찾을 때 키만 쓰지 않고 레코드 번호까지 맞춰 보는 이유는,
 *     슬롯이 재사용돼 다른 단말이 그 자리에 들어온 경우를 가려내기 위함임.
 *
 *       n2_states --has_f1_pair--> (연결, du_ue_id, record_id) --ue_find_record_id--> ue_states
 *
 * [3] 단말 표의 상태.
 *
 *     (없음) --INITIAL UL RRC--> [열림] --RELEASE COMMAND--> [해제중] --COMPLETE--> (없음)
 *                                   |                            |
 *                                   |                      유예 만료 ----------> (없음)
 *                                   +--같은 키 재등장--> 옛 레코드 버리고 새로 (UE_REPLACED)
 *                                   +--표 꽉 참------> 가장 오래된 것 축출 (UE_EVICTED)
 *
 *     RELEASE COMMAND 에서 바로 지우지 않는 이유: 그 시점에 지우면 아직 안 끝난 해제를
 *     끝난 것으로 세게 됨. COMPLETE 를 못 보면 유예 뒤에 정리함.
 *
 * [4] 가시성 관문. AS 보안이 켜진 뒤의 SRB1 은 암호문이므로 해석하지 않음.
 *
 *     암호문을 평문으로 읽으면 내용이 '그럴듯하게' 풀릴 때가 있음. 우리는 참여자가 아니라
 *     수동 관측자라 다시 달라고 할 수 없으므로, 못 읽는 것은 못 읽었다고 세는 쪽이 맞음.
 *     그래서 두 걸음임 - (1) 값을 담지 않음, (2) 담지 않은 이유마다 계수기를 올림.
 *
 * [5] F1 과 N2 짝짓기. 같은 단말이 두 인터페이스에서 다른 번호를 쓰므로 내용으로 맞춤.
 *
 *     F1 쪽 RRCSetupComplete 가 먼저 와서 대기열에 들어가고, N2 쪽 INITIAL UE MESSAGE 가
 *     그 키를 찾아감. 대기열에 둘 이상이면 고르지 않고 모호로 셈 - 절반이 오귀속이 되기 때문임.
 *
 * [6] 계약. 스레드 하나. 콜백으로 넘기는 이벤트와 그 안의 바이트는 콜백이 돌아올 때까지만 유효함.
 */
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "obs.h"
#include <libap/ap.h>
#include <librrc/rrc.h>
#include <libnas/nas.h>

// 이벤트 종류 -> 점 표기 이름. 출력과 시험에서 이벤트를 글자로 가리킬 때 씀 (types.h 선언)
const char *tr_event_name(enum tr_event_kind kind)
{
	static const char *const names[TR_EVENT__COUNT] = {
		[TR_EVENT_RRC_SETUP_REQUEST]="E.RRC.SETUP_REQUEST", [TR_EVENT_RRC_REEST_REQUEST]="E.RRC.REEST_REQUEST",
		[TR_EVENT_RRC_RESUME_REQUEST]="E.RRC.RESUME_REQUEST", [TR_EVENT_RRC_SETUP]="E.RRC.SETUP", [TR_EVENT_RRC_REJECT]="E.RRC.REJECT",
		[TR_EVENT_RRC_SETUP_COMPLETE]="E.RRC.SETUP_COMPLETE", [TR_EVENT_RRC_SMC]="E.RRC.SMC", [TR_EVENT_RRC_SMC_COMPLETE]="E.RRC.SMC_COMPLETE",
		[TR_EVENT_RRC_SMC_FAILURE]="E.RRC.SMC_FAILURE", [TR_EVENT_RRC_REEST]="E.RRC.REEST", [TR_EVENT_RRC_REEST_COMPLETE]="E.RRC.REEST_COMPLETE",
		[TR_EVENT_RRC_RESUME]="E.RRC.RESUME", [TR_EVENT_RRC_RESUME_COMPLETE]="E.RRC.RESUME_COMPLETE", [TR_EVENT_RRC_RELEASE]="E.RRC.RELEASE",
		[TR_EVENT_RRC_DCCH_OPAQUE]="E.RRC.DCCH_OPAQUE", [TR_EVENT_RRC_OTHER]="E.RRC.OTHER", [TR_EVENT_NAS_F1]="E.NAS.F1",
		[TR_EVENT_F1_UE_CTX_SETUP]="E.F1.UE_CTX_SETUP", [TR_EVENT_F1_UE_CTX_RELEASE_REQ]="E.F1.UE_CTX_RELEASE_REQ",
		[TR_EVENT_F1_UE_CTX_RELEASE_CMD]="E.F1.UE_CTX_RELEASE_CMD", [TR_EVENT_F1_UE_CTX_RELEASE_COMPLETE]="E.F1.UE_CTX_RELEASE_COMPLETE",
		[TR_EVENT_F1_RESET]="E.F1.RESET", [TR_EVENT_SCTP_ASSOC_END]="E.SCTP.ASSOC_END", [TR_EVENT_NG_INITIAL_UE_MESSAGE]="E.NG.INITIAL_UE_MESSAGE",
		[TR_EVENT_NG_AMF_DL_UE_MSG]="E.NG.AMF_DL_UE_MSG", [TR_EVENT_NG_NAS]="E.NG.NAS", [TR_EVENT_NG_UE_CTX_RELEASE_CMD]="E.NG.UE_CTX_RELEASE_CMD", [TR_EVENT_NG_UE_CTX_RELEASE_COMPLETE]="E.NG.UE_CTX_RELEASE_COMPLETE",
		[TR_EVENT_NG_OVERLOAD_START]="E.NG.OVERLOAD_START", [TR_EVENT_NG_OVERLOAD_STOP]="E.NG.OVERLOAD_STOP",
		[TR_EVENT_NG_RRC_STATE_REPORT]="E.NG.RRC_STATE_REPORT", [TR_EVENT_F1_UE_TRANSFER]="E.F1.UE_TRANSFER",
		[TR_EVENT_RRC_RECONFIG_SEC]="E.RRC.RECONFIG_SEC",
		[TR_EVENT_F1_ALG_CHANGE_OPPORTUNITY]="E.F1.ALG_CHANGE_OPPORTUNITY", [TR_EVENT_F1_CELL_CONFIG]="E.F1.CELL_CONFIG",
		[TR_EVENT_NG_SETUP]="E.NG.SETUP", [TR_EVENT_OBS_UE_EVICTED]="E.OBS.UE_EVICTED",
		[TR_EVENT_OBS_UE_REPLACED]="E.OBS.UE_REPLACED",
		[TR_EVENT_RRC_MALFORMED]="E.RRC.MALFORMED", [TR_EVENT_AP_DECODE_FAIL]="E.AP.DECODE_FAIL",
		[TR_EVENT_F1_INITIAL_UL]="E.F1.INITIAL_UL", [TR_EVENT_F1_SETUP]="E.F1.SETUP",
	};
	if (kind <= 0 || kind >= TR_EVENT__COUNT) return "?";
	return names[kind] ? names[kind] : "?";
}

// ---- 기본값 -----------------------------------------------------------------------------
#define DEF_UE_CAPACITY        131072u
#define DEF_ASSOC_CAPACITY     1024u
#define DEF_UE_TTL_S       600u
#define DEF_N2_GRACE_S     5u

/* F1AP 절차 코드 — 값은 1차 출처 asn1/f1ap-18.8.0.asn:17762-17775 (ProcedureCode ::= n) 에서 확인.
 * 이벤트를 내는 절차 9개에 P_UE_CTX_MOD_REQUIRED 를 더해 둠. 이 절차는 이벤트를 내지 않지만 방향 판정에
 * 필요함 - UEContextModificationConfirm 은 RRCContainer 를 담는 유일한 successfulOutcome 이라(위 ASN.1
 * 전수 확인) 목록에 없으면 기본 분기로 떨어져 CU->DU 메시지가 UP 으로 실림. */
enum {
	P_RESET=0,
	P_F1_SETUP=1,
	P_ERROR_INDICATION=2,
	P_GNBDU_CFG_UPD=3,
	P_UE_CTX_SETUP=5,
	P_UE_CTX_RELEASE=6,
	P_UE_CTX_MOD=7,
	P_UE_CTX_MOD_REQUIRED=8,
	P_UE_CTX_REL_REQ=10,
	P_INITIAL_UL=11,
	P_DL_RRC=12,
	P_UL_RRC=13
};

/* SCTP 목적지 포트가 IANA 지정 포트인 방향이 UP. 절차로 방향이 안 정해질 때 쓰는 보조 규칙임.
 * 근거: TS 38.472 §7 "The SCTP Destination Port number value assigned by IANA to be used for F1AP is 38472",
 *       TS 38.412 §7 "… for NGAP is 38412". 두 표준 모두 연결을 여는 쪽(F1=DU, N2=NG-RAN 노드=CU)을 정함. */
#define IANA_PORT_F1AP 38472
#define IANA_PORT_NGAP 38412

/* f1ap_proc_direction: F1AP 절차 코드 + PDU 종류로 방향을 정함. 절차가 방향을 정하지 못하면 TR_DIRECTION_UNKNOWN.
 *   이유: 절차 코드만 보면 응답의 방향을 반대로 싣게 됨. SETUP, MOD, RELEASE 를 전부 DOWN 으로 두면
 *     그 절차의 successfulOutcome(RESPONSE, COMPLETE = DU->CU)까지 DOWN 이 됨. PDU 종류를 같이 봐야
 *     개시와 응답이 갈림.
 *   근거(1차 출처): asn1/f1ap-18.8.0.asn 의 F1AP-ELEMENTARY-PROCEDURE 가 어느 메시지가 INITIATING /
 *     SUCCESSFUL OUTCOME 인지 정함(:506-533, :565-578). 개시 노드는 TS 38.473 §8.2.3(F1 Setup),
 *     §8.3.1(UE Context Setup), §8.3.3(UE Context Release), §8.3.4(UE Context Modification),
 *     §8.3.5(UE Context Modification Required), §8.4.1-3(RRC Transfer)과
 *     TS 38.472 §7("The gNB-DU shall establish the SCTP association").
 *   반환: TR_DIRECTION_DOWN(CU→DU) / TR_DIRECTION_UP(DU→CU) / TR_DIRECTION_UNKNOWN(절차로 안 정해짐 → 와이어 규칙으로).
 *     INITIATING 만 있는 절차에 successfulOutcome 이 오면(문법상 불가, 깨진 PDU) UP/DOWN 을 추측하지 않고 UNKNOWN. */
static enum tr_direction f1ap_proc_direction(long proc_code, enum f1ap_pdu_type pdu_type)
{
	bool initiating = pdu_type == F1AP_PDU_INITIATING;
	switch (proc_code) {
	// CU 가 개시: initiating = CU->DU(DOWN), 응답(successful/unsuccessful) = DU->CU(UP)
	case P_UE_CTX_SETUP:        // Request CU->DU / Response, Failure DU->CU
	case P_UE_CTX_RELEASE:      // Command CU->DU / Complete DU->CU
	case P_UE_CTX_MOD:          // Request CU->DU / Response, Failure DU->CU
		return initiating ? TR_DIRECTION_DOWN : TR_DIRECTION_UP;
	// DU 가 개시: initiating = DU->CU(UP), 응답 = CU->DU(DOWN)
	case P_F1_SETUP:            // Request DU->CU / Response, Failure CU->DU
	case P_GNBDU_CFG_UPD:       // Update DU->CU / Acknowledge, Failure CU->DU
	case P_UE_CTX_MOD_REQUIRED: // Required DU->CU / Confirm, Refuse CU->DU (Confirm 은 RRCContainer 보유)
		return initiating ? TR_DIRECTION_UP : TR_DIRECTION_DOWN;
	// INITIATING 만 있는 절차(ASN.1 에 SUCCESSFUL OUTCOME 이 없음)
	case P_DL_RRC:
		return initiating ? TR_DIRECTION_DOWN : TR_DIRECTION_UNKNOWN;
	case P_UL_RRC: case P_INITIAL_UL: case P_UE_CTX_REL_REQ:
		return initiating ? TR_DIRECTION_UP : TR_DIRECTION_UNKNOWN;
	default:
		/* Reset(0)은 CU 와 DU 가 모두 개시할 수 있어(TS 38.473 §8.2.1) 절차로는 안 정해짐.
		 * 그 밖의 절차는 개시 노드를 1차 출처로 확인하지 않았음 -> 추측하지 않고 미상으로 두고
		 * 와이어 규칙에 넘김. UP 을 돌려주면 확인하지 않은 것을 사실처럼 싣게 됨. */
		return TR_DIRECTION_UNKNOWN;
	}
}

/* wire_rule_direction: 와이어만 보고 방향을 정함.
 *   규칙: 목적지 포트가 그 인터페이스의 IANA 포트인 방향이 UP. F1 은 DU->CU(38472 가 CU), N2 는 CU->AMF(38412 가 AMF).
 *   이유: 절차로 방향이 안 정해질 때(Reset 등) 추측하지 않고 와이어에서 근거를 얻음. 상태가 필요 없어
 *     연결 중간부터 관측해도 쓸 수 있음 - SCTP INIT 을 보낸 쪽으로 가리는 방법은 그 INIT 을 봐야 함.
 *   반환: 양쪽 다 IANA 포트가 아니거나(동적 포트 쌍) 양쪽 다 IANA 포트면 TR_DIRECTION_UNKNOWN(판정 불가, 추측 금지). */
/* direction_pick: 절차 판정과 와이어 판정을 합치는 순수 규칙 — 절차가 정했으면 그것, 아니면 와이어.
 *   이유: 절차가 방향을 정하는 메시지는 정의상 정확하므로 와이어보다 앞섬. 이 세 줄을 따로 둔 까닭은
 *     시험 창(obs_direction_for_test)이 프로덕션과 같은 코드를 쓰게 하려는 것임 - 창이 판정을 복제하면
 *     창은 통과하면서 프로덕션만 틀릴 수 있음. */
static enum tr_direction direction_pick(enum tr_direction proc_direction, enum tr_direction wire_direction)
{
	return (proc_direction != TR_DIRECTION_UNKNOWN) ? proc_direction : wire_direction;
}

static enum tr_direction wire_rule_direction(const struct cap_record *record, enum tr_iface iface)
{
	if (!record) return TR_DIRECTION_UNKNOWN;
	uint16_t iana_port = (iface == TR_IFACE_N2) ? IANA_PORT_NGAP : IANA_PORT_F1AP;
	bool to_iana_port   = record->dst_port == iana_port;
	bool from_iana_port = record->src_port == iana_port;
	if (to_iana_port == from_iana_port) return TR_DIRECTION_UNKNOWN;   // 둘 다 또는 둘 다 아님 -> 가릴 수 없음
	return to_iana_port ? TR_DIRECTION_UP : TR_DIRECTION_DOWN;
}


/* NGAP 절차 코드(TS 38.413 V15.8.0 §9.4.7 Constant Definitions) — N2 이벤트 몫.
 *   값은 1차 출처 asn1/ngap-15.8.0.asn1 의 `id-<절차> ProcedureCode ::= n` 에서 확인했음. */
enum { NP_DL_NAS=4, NP_INITIAL_CONTEXT_SETUP=14, NP_INITIAL_UE_MESSAGE=15, NP_NAS_NON_DELIVERY=19, NP_NG_RESET=20,
	   NP_NG_SETUP=21, NP_OVERLOAD_START=22, NP_OVERLOAD_STOP=23, NP_PAGING=24, NP_PATH_SWITCH=25,
	   NP_PDU_SESSION_SETUP=29, NP_REROUTE_NAS=36, NP_RRC_INACTIVE_TRANSITION=37, NP_UE_CONTEXT_MODIFICATION=40,
	   NP_UE_CONTEXT_RELEASE=41, NP_UPLINK_NAS=46 };

// ---- F1 단말 레코드 ---------------------------------------------------------------------
struct obs_ue_state {
	// 키
	uint32_t assoc_id;
	uint32_t du_ue_id;      bool has_du_ue_id;
	uint32_t cu_ue_id;      bool has_cu_ue_id;   // 하행 메시지에서 학습
	uint64_t du_id;         bool du_id_is_temp;
	uint32_t crnti;         bool has_crnti;
	struct tr_nr_cgi cell;
	enum tr_prior_req prior_req;   // 재수립이나 재개 요청으로 들어왔으면 fallback 수립으로 봄
	int est_cause;                 // RRCSetupRequest 의 establishmentCause. 짝짓기 키에 들어감. -1 모름
	/* 전역에서 단조 증가하는 레코드 번호. 슬롯이 재사용돼도 번호는 재사용되지 않으므로,
	   짝을 되찾을 때 다른 단말이 우연히 같은 슬롯에 들어온 것을 가려냄 */
	uint64_t record_id;

	// 가시성 관문이 보는 보안 상태
	enum tr_sec_state rrc_sec_state;
	int ciph_alg;           // -1 모름, 0 = NEA0
	int nas_ciph_alg;       // -1 모름, 0 = 5G-EA0
	// 수명
	uint64_t created_ns, last_ns;
	bool connected;         // RRCSetupComplete 또는 RRCReestablishmentComplete 이후
	bool late_join;         // INITIAL UL 을 못 보고 등장 -> AS 보안 상태를 모름. 가시성 관문을 닫음
	/* 저장된 AS 보안 컨텍스트를 되살리는 두 경로. 둘 다 우리가 수립 때의 SECURITY MODE COMMAND 를
	   보지 못했으므로 알고리즘을 모름 -> 평문으로 가정하지 않고 암호화된 DCCH 는 해석하지 않음.
	     resumed            RRCResumeRequest 를 봄
	     reest_reactivated  RRCReestablishmentRequest 를 봄. TS 38.331 §5.3.7.4 step 9 가 Complete 를
	                        보내기 전에 SRB1 암호를 재개하게 정함
	   NEA0 로 재개한 경우에는 가시성을 잃지만, 암호문을 평문으로 오해석해 정확한 값이나 기형을
	   지어내는 것보다 나음. 둘 다 요청 메시지에서 세움 - 응답이 유실된 입력에서도 걸리게 하려는 것임 */
	bool resumed;
	bool reest_reactivated;
	/* 재수립 재활성 창에서 첫 하행 DCCH 를 이미 시험해 봤나. 그 자리의 RRCReestablishment 는
	   TS 38.331 §5.3.7.4 상 완전성 보호만 걸려 평문이라, 그 한 자리만 시험 디코드함. 뒤따르는
	   하행(암호화된 Reconfiguration 등)은 그대로 불가시로 둠. 재수립 사이클마다 한 번 */
	bool reest_grant_seen;
	/* 거짓 가독 상한. SECURITY MODE COMMAND 나 COMPLETE 를 놓치면 보안 상태가 실제보다 낮게 보이는데,
	   그 상태에서 암호문을 평문으로 읽는 것을 무한정 하지 않도록 상한을 둠. 상한을 넘으면 관문을 닫음.
	     dl_dcch_sec_none_count       하행, 보안 상태 NONE 에서 디코드한 DCCH 수
	     dl_dlinfo_exempt_count        그중 면제한 DLInformationTransfer 수(보안 전 평문 NAS 운반)
	     ul_dcch_sec_cmd_sent_count   상행, COMMAND 는 봤고 COMPLETE 는 못 본 상태에서 본 DCCH 수
	     ul_dcch_sec_none_count       상행, 보안 상태 NONE 에서 본 DCCH 수
	     ul_dlinfo_exempt_count        그중 면제한 ULInformationTransfer 수 */
	uint8_t dl_dcch_sec_none_count;
	uint8_t dl_dlinfo_exempt_count;
	uint8_t ul_dcch_sec_cmd_sent_count;
	uint8_t ul_dcch_sec_none_count, ul_dlinfo_exempt_count;
	bool releasing;         uint64_t release_cmd_ns;   // RELEASE COMMAND 를 봤고 유예 대기 중
	// 해시 체인과 LRU
	int hash_next;
	int lru_prev, lru_next;
	bool used;
};

/* ASSOC_CELL_MAX: 한 연결(= 한 DU)에서 기억해 두는 셀 수.
 *   RESET 메시지에는 셀이 실리지 않으므로, 재시작 알림의 `cells` 를 채우려면 F1 SETUP 때 본 것을
 *   들고 있어야 함. TS 38.473 의 maxCellingNBDU 는 512 지만 연결 1024개에 그만큼 두면 12MB 임.
 *   넘치면 목록 대신 '모름'(= 모든 셀)으로 떨어뜨리므로, 이 상한은 정확한 목록을 줄 수 있는 범위만
 *   정함. 8 은 테스트베드(셀 1개)와 3섹터 DU(3개)를 덮음. */
#define ASSOC_CELL_MAX 8

/* AMF_KEY_MAX: 한 센서가 구별하는 AMF 수. 한 gNB 는 자기 AMF Set 안의 AMF 들에만 붙으므로 수가 작음.
 *   넘치면 번호를 주지 않고(0 = 모름) 세며, 집계 쪽은 그 판에서만 연결 번호로 대리함. */
#define AMF_KEY_MAX 32

struct obs_assoc_record {
	uint32_t assoc_id;
	uint64_t du_id;   bool has_du_id;   // F1 SETUP 또는 DU CONFIG UPDATE 의 gNB-DU ID
	uint32_t amf_id;                   // N2 연결이면 NG SETUP RESPONSE 의 AMF Name 으로 매긴 번호. 0 = 모름
	struct tr_nr_cgi cells[ASSOC_CELL_MAX];
	int cell_count;
	bool cell_overflow;   // 상한을 넘겨 목록이 불완전함 -> 알림에 '모름' 을 실음
	bool used; int hash_next;
};

// ---- N2 단말 레코드 ---------------------------------------------------------------------
/* 키 = (AMF 엔티티, RAN-UE-NGAP-ID). RAN-UE-NGAP-ID 는 AMF 마다 따로 할당되므로 AMF 성분이 없으면
 * 다른 AMF 의 단말이 한 레코드로 합쳐짐. 구현은 AMF 를 NG-C SCTP 연결로 대리함 - 한 AMF 에 연결이
 * 하나일 때 정확하고, 한 AMF 가 연결을 여럿 쓰면 그만큼 레코드가 갈림 */
struct obs_n2_state {
	uint32_t assoc_id;                       // AMF 를 대리하는 키
	uint64_t ran_ue_ngap_id;                   // 키. RAN-UE-NGAP-ID(IE 85)
	uint64_t amf_ue_ngap_id;   bool has_amf_ue_ngap_id;   // 첫 AMF 하행 메시지에서 학습
	int nas_ciph_alg;                     // SECURITY MODE COMMAND 에서 학습. -1 모름, 0 = 5G-EA0. 가시성 관문이 봄
	int nas_ciph_alg_before_smc;          /* SMC 직전 값. 거절되면 여기로 되돌림 - TS 24.501 §5.4.2.5 :
										   * "Both the UE and the AMF shall apply the 5G NAS security context
										   * in use before the initiation of the security mode control procedure" */
	struct tr_nr_cgi cell;                // User Location Information(IE 121)
	uint64_t record_id;                         // F1 쪽과 같은 뜻. 전역 단조라 슬롯이 재사용돼도 번호는 겹치지 않음
	uint64_t created_ns, last_ns;
	bool releasing; uint64_t release_cmd_ns;    // RELEASE COMMAND 를 봤고 유예 대기 중
	/* 이 단말의 N2 연결 수립 성공을 이미 한 번 알렸나. CU 는 DL NAS TRANSPORT 나 INITIAL CONTEXT
	   SETUP 에서만 AMF 쪽 번호를 실어 주므로, 그 두 자리에서만 성공을 알 수 있고 한 번만 알림 */
	bool uecntx_succ_sent;
	bool has_f1_pair; uint32_t f1_pair_assoc; uint32_t f1_pair_du_ue_id; uint64_t f1_pair_record_id;
	bool used; int hash_next; int lru_prev, lru_next;
};

// ---- F1 RRCSetupComplete 와 N2 INITIAL UE MESSAGE 짝짓기 --------------------------------

// 대기 중인 F1 항목 하나. (assoc_id, du_ue_id, f1_record_id)가 ue_find_record_id 로 되찾을 때의 키임
struct corr_item { uint64_t wallclock_ns; uint64_t f1_record_id; uint32_t assoc_id; uint32_t du_ue_id; int next_index; bool used; };
struct corr_key {
	uint32_t plmn_packed; uint64_t cell_id; int est_cause; uint32_t nas_ie_len; uint64_t hash_lo, hash_hi;   // PLMN 과 셀 번호를 합쳐 NR CGI
	uint64_t ambiguous_until_ns;        // 모호 표지 만료 시각. 그때까지 같은 키는 모두 모호로 셈
	int item_head; int pending_count;      // 대기 F1 항목 단일 연결 리스트의 머리와 그 수
	bool used; int hash_next;
};

struct obs {
	struct obs_cfg obs_cfg;
	obs_event_cb on_event; void *user_ctx;
	struct obs_stats stats;
	uint64_t now_ns;
	uint64_t last_sweep_ns;   // 만료 훑기를 메시지마다 하지 않고 최소 간격을 둠. 훑기 비용이 표 크기에 비례해서임

	// AMF 신원에서 키 번호로. 자세한 것은 amf_id_for 주석
	struct { uint64_t name_hash; uint32_t amf_id; bool used; } amf_keys[AMF_KEY_MAX];
	uint32_t amf_key_count;

	// F1 단말 표. 배열 + 해시 체인 + 빈 칸 목록 + LRU
	struct obs_ue_state *ue_states; uint32_t ue_capacity;
	int *ue_hash_buckets; uint32_t ue_hash_bucket_count;
	int ue_free;                 // 빈 칸 목록의 머리. -1 이면 없음
	int lru_head, lru_tail;      // head 가 가장 오래된 것, tail 이 가장 최근
	uint32_t ue_count;

	// SCTP 연결 표
	struct obs_assoc_record *assoc_records; uint32_t assoc_capacity; int *assoc_hash_buckets; uint32_t assoc_hash_bucket_count; int assoc_free;

	// N2 단말 표. F1 표와 같은 구조
	struct obs_n2_state *n2_states; uint32_t n2_capacity; int *n2_hash_buckets; uint32_t n2_hash_bucket_count;
	int n2_free, n2_lru_head, n2_lru_tail; uint32_t n2_count;

	// 짝짓기. 키 버킷 해시와 대기 F1 항목 풀
	struct corr_key *corr_keys; uint32_t corr_key_capacity; int *corr_key_hash_buckets; uint32_t corr_key_hash_bucket_count; int corr_key_free;
	struct corr_item *corr_items; uint32_t corr_item_capacity; int corr_item_free;
	uint64_t correlation_window_ns;

	uint64_t next_record_id;   // 레코드 번호 발급기. 0 은 무효라 첫 발급이 1
};

/* decide_direction: 절차 -> 와이어 -> 미상 순서로 방향을 정하고, 둘이 어긋나면 셈.
 *   이유: 절차가 방향을 정하는 메시지(DL RRC MESSAGE TRANSFER 등)는 절차 쪽이 정의상 정확하므로 먼저 씀.
 *     와이어 규칙은 절차가 못 정하는 경우(Reset)를 메우고, 둘 다 알 때는 서로 대조가 됨. 어긋남은
 *     관측 지점이나 상대가 비정상이라는 신호이므로 세어 보고함.
 *   부작용: obs->stats.direction_conflict_count 와 direction_unknown_count 를 갱신함. 미상과 불일치를
 *     조용히 넘기면 '그런 일이 없었음' 과 같은 모양이 됨. */
static enum tr_direction decide_direction(struct obs *obs, const struct cap_record *record,
									enum tr_iface iface, enum tr_direction proc_direction)
{
	enum tr_direction wire_direction = wire_rule_direction(record, iface);
	if (proc_direction != TR_DIRECTION_UNKNOWN && wire_direction != TR_DIRECTION_UNKNOWN && proc_direction != wire_direction)
		obs->stats.direction_conflict_count++;
	enum tr_direction direction = direction_pick(proc_direction, wire_direction);
	if (direction == TR_DIRECTION_UNKNOWN) obs->stats.direction_unknown_count++;
	return direction;
}

// ---- 작은 해시 --------------------------------------------------------------------------
static uint32_t ue_bucket(uint32_t assoc_id, uint32_t du_ue_id, uint32_t bucket_count)
{
	uint64_t hash_key = ((uint64_t)assoc_id << 32) | du_ue_id;
	hash_key = (hash_key ^ (hash_key >> 30)) * 0xbf58476d1ce4e5b9ULL; hash_key ^= hash_key >> 27;
	return (uint32_t)(hash_key % bucket_count);
}
static uint32_t assoc_bucket(uint32_t assoc_id, uint32_t bucket_count) { return (assoc_id * 2654435761u) % bucket_count; }

// ---- 이벤트 헤더 채우기 -----------------------------------------------------------------
static void fill_event_header(struct obs_event *event, const struct obs *obs, const struct sctp_message *sctp_message,
				 enum tr_event_kind kind, enum tr_direction direction)
{
	memset(event, 0, sizeof *event);
	event->kind = kind;
	event->wallclock_ns = sctp_message->record ? sctp_message->record->capture_time_ns : obs->now_ns;
	event->iface = TR_IFACE_F1;
	event->direction = direction;
	event->assoc_id = sctp_message->assoc_id;
	event->quality = TR_QUALITY_EXACT;
}
// f1ue_key_of: 단말 상태에서 F1 키만 꺼냄. 셀은 담지 않음 - RESET 목록처럼 키만 필요한 자리가 있음
static struct tr_f1ue f1ue_key_of(const struct obs_ue_state *ue_state)
{
	struct tr_f1ue f1ue = {
		.valid        = true,
		.du_id        = ue_state->du_id,
		.du_id_is_temp = ue_state->du_id_is_temp,
		.du_ue_id     = ue_state->du_ue_id,
	};
	if (ue_state->has_cu_ue_id) { f1ue.has_cu_ue_id = true; f1ue.cu_ue_id = ue_state->cu_ue_id; }
	if (ue_state->has_crnti)    { f1ue.has_crnti = true;    f1ue.crnti = ue_state->crnti; }
	return f1ue;
}
static void fill_f1ue(struct obs_event *event, const struct obs_ue_state *ue_state)
{
	event->f1ue = f1ue_key_of(ue_state);
	event->cell = ue_state->cell;
}
// emit: 이벤트 하나를 위로 올림. 이벤트가 나가는 자리가 여기뿐이라 여기서 세면 빠뜨릴 수 없음
static void emit(struct obs *obs, const struct obs_event *event)
{
	obs->stats.event_emitted_count++;
	if (obs->on_event)
		obs->on_event(obs->user_ctx, event);
}

// ---- LRU --------------------------------------------------------------------------------
static void lru_unlink(struct obs *obs, int i)
{
	struct obs_ue_state *ue_state = &obs->ue_states[i];
	if (ue_state->lru_prev >= 0) obs->ue_states[ue_state->lru_prev].lru_next = ue_state->lru_next; else obs->lru_head = ue_state->lru_next;
	if (ue_state->lru_next >= 0) obs->ue_states[ue_state->lru_next].lru_prev = ue_state->lru_prev; else obs->lru_tail = ue_state->lru_prev;
	ue_state->lru_prev = ue_state->lru_next = -1;
}
static void lru_push_tail(struct obs *obs, int i)
{
	struct obs_ue_state *ue_state = &obs->ue_states[i];
	ue_state->lru_prev = obs->lru_tail; ue_state->lru_next = -1;
	if (obs->lru_tail >= 0) obs->ue_states[obs->lru_tail].lru_next = i; else obs->lru_head = i;
	obs->lru_tail = i;
}
static void lru_touch(struct obs *obs, int i) { lru_unlink(obs, i); lru_push_tail(obs, i); }

// ---- F1 단말 표 조회, 생성, 제거 --------------------------------------------------------
static int ue_find(struct obs *obs, uint32_t assoc_id, uint32_t du_ue_id)
{
	for (int i = obs->ue_hash_buckets[ue_bucket(assoc_id, du_ue_id, obs->ue_hash_bucket_count)]; i >= 0; i = obs->ue_states[i].hash_next)
		if (obs->ue_states[i].used && obs->ue_states[i].assoc_id == assoc_id && obs->ue_states[i].has_du_ue_id && obs->ue_states[i].du_ue_id == du_ue_id)
			return i;
	return -1;
}
/* ue_find_record_id: 키로 슬롯을 찾되 레코드 번호가 다르면 없는 것으로 봄.
 *   이유: 키만 맞춰 보면 그 사이에 슬롯이 재사용돼 다른 단말이 들어온 경우를 가릴 수 없어, 짝을
 *     엉뚱한 단말에 붙이게 됨. 레코드 번호는 전역 단조라 슬롯마다 세대를 두는 방법과 달리
 *     '다른 슬롯이 우연히 같은 세대' 인 경우까지 막음. */
static int ue_find_record_id(struct obs *obs, uint32_t assoc_id, uint32_t du_ue_id, uint64_t record_id)
{
	int i = ue_find(obs, assoc_id, du_ue_id);
	return (i >= 0 && obs->ue_states[i].record_id == record_id) ? i : -1;
}
static void ue_hash_remove(struct obs *obs, int idx)
{
	uint32_t bucket = ue_bucket(obs->ue_states[idx].assoc_id, obs->ue_states[idx].du_ue_id, obs->ue_hash_bucket_count);
	int *hash_link = &obs->ue_hash_buckets[bucket];
	while (*hash_link >= 0) { if (*hash_link == idx) { *hash_link = obs->ue_states[idx].hash_next; return; } hash_link = &obs->ue_states[*hash_link].hash_next; }
}
// ue_remove: 표에서만 지움. 이벤트는 호출자가 냄
static void ue_remove(struct obs *obs, int idx)
{
	ue_hash_remove(obs, idx);
	lru_unlink(obs, idx);
	obs->ue_states[idx].used = false;
	obs->ue_states[idx].hash_next = obs->ue_free; obs->ue_free = idx;
	obs->ue_count--;
}
// ue_evict_one: 표가 꽉 찼을 때 가장 오래된 레코드를 지우고 그 사실을 이벤트로 알림
static void ue_evict_one(struct obs *obs)
{
	int i = obs->lru_head; if (i < 0) return;
	struct obs_event event; memset(&event, 0, sizeof event);
	event.kind = TR_EVENT_OBS_UE_EVICTED; event.wallclock_ns = obs->now_ns; event.iface = TR_IFACE_F1; event.assoc_id = obs->ue_states[i].assoc_id;
	fill_f1ue(&event, &obs->ue_states[i]);
	emit(obs, &event);
	obs->stats.ue_evicted_count++;
	ue_remove(obs, i);
}
static int ue_create(struct obs *obs, uint32_t assoc_id, uint32_t du_ue_id)
{
	if (obs->ue_count >= obs->obs_cfg.ue_capacity) ue_evict_one(obs);
	if (obs->ue_free < 0) return -1;
	int i = obs->ue_free; obs->ue_free = obs->ue_states[i].hash_next;
	struct obs_ue_state *ue_state = &obs->ue_states[i];
	memset(ue_state, 0, sizeof *ue_state);
	ue_state->record_id = ++obs->next_record_id;
	ue_state->used = true; ue_state->assoc_id = assoc_id; ue_state->du_ue_id = du_ue_id; ue_state->has_du_ue_id = true;
	ue_state->ciph_alg = -1; ue_state->nas_ciph_alg = -1; ue_state->rrc_sec_state = TR_SEC_NONE; ue_state->est_cause = -1;
	ue_state->created_ns = ue_state->last_ns = obs->now_ns;
	ue_state->lru_prev = ue_state->lru_next = -1;
	uint32_t bucket = ue_bucket(assoc_id, du_ue_id, obs->ue_hash_bucket_count);
	ue_state->hash_next = obs->ue_hash_buckets[bucket]; obs->ue_hash_buckets[bucket] = i;
	lru_push_tail(obs, i);
	obs->ue_count++;
	return i;
}

// ---- SCTP 연결에서 DU 로 가는 매핑 ------------------------------------------------------
static struct obs_assoc_record *assoc_get(struct obs *obs, uint32_t assoc_id)
{
	uint32_t bucket = assoc_bucket(assoc_id, obs->assoc_hash_bucket_count);
	for (int i = obs->assoc_hash_buckets[bucket]; i >= 0; i = obs->assoc_records[i].hash_next)
		if (obs->assoc_records[i].used && obs->assoc_records[i].assoc_id == assoc_id) return &obs->assoc_records[i];
	/* 상한 도달: 새 연결의 DU 매핑을 만들지 않음. 그 연결의 단말은 임시 DU 키로 떨어짐.
	 * 조용히 버리면 "DU 를 못 봤음" 과 "표가 꽉 찼음" 을 구분할 수 없어 세어 둠 */
	if (obs->assoc_free < 0) { obs->stats.assoc_table_full_count++; return NULL; }
	int i = obs->assoc_free; obs->assoc_free = obs->assoc_records[i].hash_next;
	memset(&obs->assoc_records[i], 0, sizeof obs->assoc_records[i]);
	obs->assoc_records[i].used = true; obs->assoc_records[i].assoc_id = assoc_id;
	obs->assoc_records[i].hash_next = obs->assoc_hash_buckets[bucket]; obs->assoc_hash_buckets[bucket] = i;
	return &obs->assoc_records[i];
}
/* assoc_remove: 연결이 끝나면 그 레코드를 돌려줌.
 *   이유: 안 지우면 재접속과 vtag 재시작이 쌓여 표가 소진되고, 그 뒤 모든 단말이 임시 DU 키로 떨어짐. */
static void assoc_remove(struct obs *obs, uint32_t assoc_id)
{
	uint32_t bucket = assoc_bucket(assoc_id, obs->assoc_hash_bucket_count);
	int *hash_link = &obs->assoc_hash_buckets[bucket];
	while (*hash_link >= 0) {
		int i = *hash_link;
		if (obs->assoc_records[i].used && obs->assoc_records[i].assoc_id == assoc_id) {
			*hash_link = obs->assoc_records[i].hash_next; obs->assoc_records[i].used = false;
			obs->assoc_records[i].hash_next = obs->assoc_free; obs->assoc_free = i; return;
		}
		hash_link = &obs->assoc_records[i].hash_next;
	}
}

// set_f1ue_keys: gNB-DU ID 를 아직 못 봤으면 연결 번호를 임시 키로 씀
static void set_f1ue_keys(struct obs *obs, struct obs_ue_state *ue_state)
{
	struct obs_assoc_record *assoc_record = assoc_get(obs, ue_state->assoc_id);
	if (assoc_record && assoc_record->has_du_id) { ue_state->du_id = assoc_record->du_id; ue_state->du_id_is_temp = false; }
	else { ue_state->du_id = ue_state->assoc_id; ue_state->du_id_is_temp = true; }
}

// ---- 가시성 관문 ------------------------------------------------------------------------
/*
 * SRB1 이상의 DCCH 를 평문으로 해석해도 되는지 판정함. 암호문도 UPER 로 그럴듯하게 풀려서
 * 무작위 바이트의 24~46% 가 메시지 이름까지 얻음 - 암호가 걸렸을 수 있으면 풀지 않고 OPAQUE 로 올림.
 * 안 막으면 가짜 이벤트와 가짜 품질 등급이 나감.
 *
 *     AS 보안 상태                 방향    판정      쓰는 예산 칸
 *     ciph_alg == 0 (NEA0)         무관    가독      없음. 암호가 안 걸린 것이 확정임
 *     무엇이든                     미상    OPAQUE    없음
 *     NONE, 앞을 다 본 단말        하행    1개까지   dl_dcch_sec_none_count
 *     NONE, 앞을 다 본 단말        상행    1개까지   ul_dcch_sec_none_count
 *     CMD_SENT                     상행    1개까지   ul_dcch_sec_cmd_sent_count
 *     CMD_SENT                     하행    OPAQUE    없음
 *     ACTIVE 이고 암호             무관    OPAQUE    없음
 *     late_join, resumed, 재수립    무관    OPAQUE    없음. 앞 구간을 못 봐 보안 상태를 모름
 *
 * 예산 칸이 왜 있나: SecurityModeCommand 와 SecurityModeComplete 를 둘 다 놓치면 rrc_sec_state 가
 * NONE 에 머물러, 뒤에 오는 암호문이 전부 '보안 전 평문' 으로 읽힘. 연결 뒤에 평문으로 기대되는
 * DCCH 는 SecurityModeCommand 하나뿐이고 그것을 풀면 상태가 CMD_SENT 로 올라가 이 가지를 벗어나므로,
 * 연결 뒤 두 번째부터는 놓친 것으로 보고 닫음. 완전 관측 세션은 걸리지 않음.
 *
 * 예산 면제: 평문으로 여러 번 오는 것이 정상인 NAS 운반(DLInformationTransfer, ULInformationTransfer)은
 * 상한까지 예산을 쓰지 않음. 5G-AKA 는 보안 전 NAS 가 1~3회지만 사설 5G 의 EAP-TLS, EAP-AKA' 는
 * TLS 핸드셰이크를 여러 EAP-Request NAS 로 쪼개 그보다 많음. 상한에 걸려 닫히면
 * dcch_gate_closed_on_cap_count 로 카운팅해 긴 인증과 진짜 SMC 유실을 가름.
 */
#define DL_DCCH_EXEMPT_DEFAULT 16   // 면제 상한 기본값. EAP 인증이 쪼개 보내는 NAS 수를 덮는 값

static bool dcch_visible(const struct obs_ue_state *ue_state, enum tr_direction direction)
{
	if (ue_state->ciph_alg == 0) return true;   // NEA0 확인됨. 방향과 무관하게 읽힘
	/* 방향 미상은 fail-closed. 예산 칸이 전부 확정 방향에서만 올라가므로 미상이 이 가지에 들어오면
	 * 상한이 작동하지 않고, 미상이 확정 방향보다 더 열린 상태가 됨. 오늘의 문법에서는 RRC 컨테이너를
	 * 싣는 F1AP 메시지 7종이 모두 방향이 정해져 있어 도달하지 않지만, 안전이 그 문법 사실에 기대지
	 * 않게 여기서 막음. */
	if (direction == TR_DIRECTION_UNKNOWN) return false;
	if (ue_state->rrc_sec_state == TR_SEC_NONE && !ue_state->late_join && !ue_state->resumed && !ue_state->reest_reactivated) {   // 보안 전이고 앞 구간을 다 본 단말
		if (direction == TR_DIRECTION_DOWN && ue_state->connected && ue_state->dl_dcch_sec_none_count >= 1) return false;
		if (direction == TR_DIRECTION_UP   && ue_state->connected && ue_state->ul_dcch_sec_none_count >= 1) return false;   // 상행도 같게 막음
		return true;
	}
	/* CMD_SENT 에서 평문으로 올 수 있는 상행은 SecurityModeComplete 나 SecurityModeFailure 하나뿐임.
	 * Complete 를 놓쳐 CMD_SENT 에 고착되면 뒤따르는 상행은 암호문이므로 첫 1개만 허용함. */
	if (ue_state->rrc_sec_state == TR_SEC_CMD_SENT && direction == TR_DIRECTION_UP) return ue_state->ul_dcch_sec_cmd_sent_count == 0;
	return false;   // late_join, CMD_SENT 의 하행, 활성이고 암호 -> fail-closed
}

// RRC 메시지 이름을 이벤트 종류로 옮김. 못 찾으면 TR_EVENT_RRC_OTHER
static enum tr_event_kind rrc_kind(const struct rrc_msg *rrc_msg)
{
	const char *msg_name = rrc_msg->msg_name ? rrc_msg->msg_name : "";
	if (!strcmp(msg_name, "RRCSetupRequest"))            return TR_EVENT_RRC_SETUP_REQUEST;
	if (!strcmp(msg_name, "RRCReestablishmentRequest"))  return TR_EVENT_RRC_REEST_REQUEST;
	if (!strcmp(msg_name, "RRCResumeRequest") || !strcmp(msg_name, "RRCResumeRequest1")) return TR_EVENT_RRC_RESUME_REQUEST;
	if (!strcmp(msg_name, "RRCSetup"))                   return TR_EVENT_RRC_SETUP;
	if (!strcmp(msg_name, "RRCReject"))                  return TR_EVENT_RRC_REJECT;
	if (!strcmp(msg_name, "RRCSetupComplete"))           return TR_EVENT_RRC_SETUP_COMPLETE;
	if (!strcmp(msg_name, "SecurityModeCommand"))        return TR_EVENT_RRC_SMC;
	if (!strcmp(msg_name, "SecurityModeComplete"))       return TR_EVENT_RRC_SMC_COMPLETE;
	if (!strcmp(msg_name, "SecurityModeFailure"))        return TR_EVENT_RRC_SMC_FAILURE;
	if (!strcmp(msg_name, "RRCReestablishment"))         return TR_EVENT_RRC_REEST;
	if (!strcmp(msg_name, "RRCReestablishmentComplete")) return TR_EVENT_RRC_REEST_COMPLETE;
	if (!strcmp(msg_name, "RRCResume"))                  return TR_EVENT_RRC_RESUME;
	if (!strcmp(msg_name, "RRCResumeComplete"))          return TR_EVENT_RRC_RESUME_COMPLETE;
	if (!strcmp(msg_name, "RRCRelease"))                 return TR_EVENT_RRC_RELEASE;
	if (!strcmp(msg_name, "RRCReconfiguration"))         return TR_EVENT_RRC_RECONFIG_SEC;   // securityConfig 유무는 handle_rrc_container 에서 가름
	return TR_EVENT_RRC_OTHER;
}

// ---- 매칭 대기 항목과 시간창 ------------------------------------------------------------
// NAS 바이트의 128비트 해시. 독립된 64비트 누산기 둘을 씀. 적대적 충돌을 막는 키 해시는 아직 아님
static void nas_hash128(const uint8_t *bytes, size_t len, uint64_t *hash_lo, uint64_t *hash_hi)
{
	uint64_t state_a = 1469598103934665603ULL, state_c = 1099511628211ULL;
	uint64_t state_d = 1125899906842597ULL;
	for (size_t i = 0; i < len; i++) { state_a = (state_a ^ bytes[i]) * state_c; state_d = (state_d ^ bytes[i]) * 31ULL; state_d ^= state_d >> 29; }
	state_a ^= state_a >> 33; state_a *= 0xff51afd7ed558ccdULL; state_a ^= state_a >> 33;
	state_d ^= (uint64_t)len * 0x9e3779b97f4a7c15ULL; state_d ^= state_d >> 29;   // hash_hi 는 state_d 만 씀. state_a 에 기대면 두 값이 같이 틀림
	*hash_lo = state_a; *hash_hi = state_d;
}
static uint32_t plmn_pack(const uint8_t plmn_bytes[3]) { return ((uint32_t)plmn_bytes[0] << 16) | ((uint32_t)plmn_bytes[1] << 8) | plmn_bytes[2]; }
static uint32_t corr_key_bucket(uint32_t plmn_packed, uint64_t cell_id, int est_cause, uint32_t nas_ie_len, uint64_t hash_lo, uint32_t bucket_count)
{
	uint64_t hash_key = cell_id ^ ((uint64_t)plmn_packed << 20) ^ ((uint64_t)(uint32_t)est_cause << 48) ^ ((uint64_t)nas_ie_len << 32) ^ hash_lo;
	hash_key = (hash_key ^ (hash_key >> 30)) * 0xbf58476d1ce4e5b9ULL; hash_key ^= hash_key >> 27;
	return (uint32_t)(hash_key % bucket_count);
}
static struct corr_key *corr_key_get(struct obs *obs, uint32_t plmn_packed, uint64_t cell_id, int est_cause, uint32_t nas_ie_len,
							   uint64_t hash_lo, uint64_t hash_hi, bool create_if_missing)
{
	uint32_t bucket = corr_key_bucket(plmn_packed, cell_id, est_cause, nas_ie_len, hash_lo, obs->corr_key_hash_bucket_count);
	for (int i = obs->corr_key_hash_buckets[bucket]; i >= 0; i = obs->corr_keys[i].hash_next)
		if (obs->corr_keys[i].used && obs->corr_keys[i].plmn_packed == plmn_packed && obs->corr_keys[i].cell_id == cell_id && obs->corr_keys[i].est_cause == est_cause &&
			obs->corr_keys[i].nas_ie_len == nas_ie_len && obs->corr_keys[i].hash_lo == hash_lo && obs->corr_keys[i].hash_hi == hash_hi) return &obs->corr_keys[i];
	if (!create_if_missing || obs->corr_key_free < 0) return NULL;
	int i = obs->corr_key_free; obs->corr_key_free = obs->corr_keys[i].hash_next;
	struct corr_key *corr_key = &obs->corr_keys[i]; memset(corr_key, 0, sizeof *corr_key);
	corr_key->used = true; corr_key->plmn_packed = plmn_packed; corr_key->cell_id = cell_id; corr_key->est_cause = est_cause; corr_key->nas_ie_len = nas_ie_len; corr_key->hash_lo = hash_lo; corr_key->hash_hi = hash_hi;
	corr_key->item_head = -1;
	corr_key->hash_next = obs->corr_key_hash_buckets[bucket]; obs->corr_key_hash_buckets[bucket] = i;
	return corr_key;
}
static void corr_key_free_if_empty(struct obs *obs, struct corr_key *corr_key, uint64_t now_ns)
{
	if (corr_key->item_head >= 0 || corr_key->ambiguous_until_ns >= now_ns) return;
	int idx = (int)(corr_key - obs->corr_keys);
	uint32_t bucket = corr_key_bucket(corr_key->plmn_packed, corr_key->cell_id, corr_key->est_cause, corr_key->nas_ie_len, corr_key->hash_lo, obs->corr_key_hash_bucket_count);
	int *hash_link = &obs->corr_key_hash_buckets[bucket];
	while (*hash_link >= 0) { if (*hash_link == idx) { *hash_link = obs->corr_keys[idx].hash_next; break; } hash_link = &obs->corr_keys[*hash_link].hash_next; }
	corr_key->used = false; corr_key->hash_next = obs->corr_key_free; obs->corr_key_free = idx;
}
static void corr_item_free_one(struct obs *obs, int item_index) { obs->corr_items[item_index].used = false; obs->corr_items[item_index].next_index = obs->corr_item_free; obs->corr_item_free = item_index; }
// 버킷에서 시간창이 지난 F1 항목을 빼고 corr_unmatched_f1_count 로 카운팅
static void corr_key_expire_items(struct obs *obs, struct corr_key *corr_key, uint64_t now_ns)
{
	int *item_link = &corr_key->item_head;
	while (*item_link >= 0) {
		struct corr_item *corr_item = &obs->corr_items[*item_link];
		if (corr_item->wallclock_ns + obs->correlation_window_ns < now_ns) { int next_index = corr_item->next_index; corr_item_free_one(obs, *item_link); *item_link = next_index; corr_key->pending_count--; obs->stats.corr_unmatched_f1_count++; }
		else item_link = &corr_item->next_index;
	}
}
// 모든 버킷의 시간창 만료 처리. obs_advance 가 부름
static void corr_expire(struct obs *obs, uint64_t now_ns)
{
	for (uint32_t i = 0; i < obs->corr_key_capacity; i++) {
		if (!obs->corr_keys[i].used) continue;
		corr_key_expire_items(obs, &obs->corr_keys[i], now_ns);
		corr_key_free_if_empty(obs, &obs->corr_keys[i], now_ns);
	}
}
/* CORR_EST_CAUSE_ANY: 매칭 키의 원인 칸에 쓰는 '원인 모름' 값.
 *   F1 쪽이 RRCReestablishmentRequest 나 RRCResumeRequest 뒤 RRCSetup 으로 폴백한 세션은
 *   RRCSetupRequest 가 없어 establishmentCause 를 모름. 그런데 CU 는 INITIAL UE MESSAGE 에 어떤
 *   RRCEstablishmentCause 든 실어 보냄 - TS 38.413 §9.3.1.111 이 폴백 때의 값을 정하지 않음
 *   (실측: OCUDU 가 otherFailure(2) 자리에 mt-Access(2) 를 보냄). 그래서 폴백 세션은 원인 없는 키로
 *   등록하고, N2 쪽은 정확한 키가 없을 때 이 키를 한 번 더 찾음. 셀과 NAS 길이와 NAS 128비트 해시가
 *   남아 있어 오귀속 위험은 원인 칸 하나만큼만 늘어남 */
#define CORR_EST_CAUSE_ANY (-1)

/* corr_on_f1: RRCSetupComplete 의 NAS 로 매칭 키를 만들어 대기열에 넣음.
 *   est_cause 가 -1 이면 fallback_without_cause 가 참일 때만 CORR_EST_CAUSE_ANY 키로 등록함.
 *   RRCSetupRequest 를 못 본 late-join 은 등록하지 않음 - 원인을 모르는 이유가 폴백이 아니라 우리가
 *   앞을 놓친 것이라, 아무 키에나 붙이면 남의 단말에 귀속됨. */
static void corr_on_f1(struct obs *obs, const struct tr_nr_cgi *cell, int est_cause, bool fallback_without_cause, const uint8_t *nas_bytes, uint32_t nas_ie_len,
					   uint64_t wallclock_ns, uint32_t assoc_id, uint32_t du_ue_id, uint64_t record_id)
{
	if (est_cause < 0 && fallback_without_cause) est_cause = CORR_EST_CAUSE_ANY;
	if (!nas_bytes || nas_ie_len == 0 || est_cause < CORR_EST_CAUSE_ANY || (est_cause < 0 && !fallback_without_cause) || !cell || !cell->valid) return;   // 키를 만들 수 없음 -> 매칭하지 않음
	uint32_t plmn_packed = plmn_pack(cell->plmn_bytes);
	uint64_t hash_lo, hash_hi; nas_hash128(nas_bytes, nas_ie_len, &hash_lo, &hash_hi);
	struct corr_key *corr_key = corr_key_get(obs, plmn_packed, cell->cell_id, est_cause, nas_ie_len, hash_lo, hash_hi, true);
	if (!corr_key) { obs->stats.corr_expired_count++; obs->stats.corr_queue_overflow_count++; return; }   // 키 풀 소진. 버린 이유마다 따로 카운팅
	if (corr_key->ambiguous_until_ns >= wallclock_ns) { obs->stats.corr_ambiguous_count++; corr_key->ambiguous_until_ns = wallclock_ns + obs->correlation_window_ns; return; }
	if (obs->corr_item_free < 0) { obs->stats.corr_expired_count++; obs->stats.corr_queue_overflow_count++; return; }   // 항목 풀 소진
	int i = obs->corr_item_free; obs->corr_item_free = obs->corr_items[i].next_index;
	struct corr_item *corr_item = &obs->corr_items[i];
	corr_item->used = true; corr_item->wallclock_ns = wallclock_ns; corr_item->assoc_id = assoc_id; corr_item->du_ue_id = du_ue_id; corr_item->f1_record_id = record_id;
	corr_item->next_index = corr_key->item_head; corr_key->item_head = i; corr_key->pending_count++;
}

/* nas_accept_result: nas_parse 결과를 받아들임 - 이유별 계수기를 통계에 더하고, 메시지 타입을 담아도
 *   되는지 판정함. 세 호출 지점(F1 RRCSetupComplete, NGAP INITIAL UE MESSAGE, NGAP NAS 운반)이 같은
 *   일을 하므로 한 곳으로 모았음.
 *   계수기는 nas_parse 가 실패를 돌려준 경우에도 유효함(libnas 의 계약) -> 성공과 실패 양쪽에서 부름.
 *   방향 판정의 근거 — TS 24.501 §7.4 NOTE: "A message type not defined for the EPD in the given direction
 *   is regarded by the receiver as a message type not defined for the EPD". 방향이 어긋난 타입은 AMF 가
 *   모르는 타입으로 버리므로 우리도 담지 않음. 담으면 단말이 하행 전용 메시지(SERVICE ACCEPT 등)를
 *   상행으로 보내 표 I 의 5GMM 주상태를 깎이지 않은 등급으로 조작할 수 있음(tr 이 타입만 보고 전이함).
 *   방향을 모르면 어긋남을 증명할 수 없으므로 담고, 판정하지 못했다는 사실을 따로 카운팅함(fail-closed
 *   두 걸음).
 *   같은 상황에서 SHT 4 추론은 거꾸로 거부함 — 비대칭이 아니라 다루는 것이 다름. 여기 담는 것은
 *   와이어에서 읽은 값이고, 추론은 우리가 만든 값임. 읽은 값은 방향을 몰라도 상대가 보낸 사실이지만,
 *   만든 값은 전제를 확인하지 못하면 근거가 없음.
 *   반환: true = msg_type 을 담아도 됨(호출자가 msg_type_usable 로 받음). 부작용: obs->stats 갱신. */
static bool nas_accept_result(struct obs *obs, const struct nas_msg *nas_msg, enum tr_direction direction)
{
	obs->stats.nas_truncated_count           += (uint64_t)nas_msg->truncated_count;
	obs->stats.nas_epd_mismatch_count        += (uint64_t)nas_msg->epd_mismatch_count;
	obs->stats.nas_reserved_sht_count        += (uint64_t)nas_msg->reserved_sht_count;
	obs->stats.nas_unknown_msg_type_count    += (uint64_t)nas_msg->unknown_msg_type_count;
	obs->stats.nas_missing_mandatory_ie_count += (uint64_t)nas_msg->missing_mandatory_ie_count;
	obs->stats.nas_rejected_ie_count         += (uint64_t)nas_msg->rejected_ie_count;
	obs->stats.nas_ie_scan_aborted_count     += (uint64_t)nas_msg->ie_scan_aborted_count;
	obs->stats.nas_unknown_tlve_iei_count    += (uint64_t)nas_msg->unknown_tlve_iei_count;
	obs->stats.nas_inner_not_plain_count     += (uint64_t)nas_msg->inner_not_plain_count;
	if (nas_msg->msg_type < 0) return false;
	if (direction == TR_DIRECTION_UNKNOWN) { obs->stats.nas_direction_unjudged_count++; return true; }
	bool conflicts = (nas_msg->msg_type_direction == NAS_MSG_DIR_UE_TO_NETWORK  && direction == TR_DIRECTION_DOWN)
				  || (nas_msg->msg_type_direction == NAS_MSG_DIR_NETWORK_TO_UE && direction == TR_DIRECTION_UP);
	if (conflicts) { obs->stats.nas_direction_mismatch_count++; return false; }
	return true;
}

/* nas_values_init: 정수 칸을 전부 '안 읽음'(-1)으로 둠.
 *   이유: 이벤트는 memset 으로 0 이 되는데 0 은 이 칸들에서 전부 정상값임(SHT 0 = 평문,
 *     알고리즘 0 = NEA0, 신원 종류 0 = No identity, Switch off 0 = normal detach). 0 을 그대로 두면
 *     NAS 를 못 읽은 줄이 '평문 NAS 를 봤음'로 읽힘.
 *   sec_header_direction_ok 만 참으로 두는 것은 제약 없는 SHT 의 기본값이기 때문임 —
 *     짝 판정이 어긋난 자리에서만 내림. */
static void nas_values_init(struct obs_nas_values *nas)
{
	memset(nas, 0, sizeof *nas);
	nas->epd = -1;      nas->sht = -1;        nas->msg_type = -1;
	nas->reg_type = -1; nas->id_type = -1;    nas->switch_off = -1; nas->mm_cause = -1;
	nas->smc_ciph_alg = -1; nas->smc_integ_alg = -1;
	nas->sec_header_direction_ok = true;
}

/* nas_values_take: libnas 가 푼 결과에서 이벤트가 싣는 NAS 값을 옮김.
 *   이유: F1 의 초기 NAS 와 N2 의 NAS 를 탐지 엔진은 같은 표로 읽음. 옮기는 곳이 둘로 갈려 있으면
 *     한쪽에만 값이 빠지고, 빠진 쪽은 엔진에서 '그 값이 없었음' 과 같은 모양이 됨 — 실제로 F1 경로는
 *     일곱 칸 중 reg_type 하나만 옮기고 있었음.
 *   msg_type_usable: 메시지 종류를 담아도 되는지. 거짓이면 -1 로 남김(이름표가 관문). */
static void nas_values_take(struct obs_nas_values *nas, const struct nas_msg *nas_msg, bool msg_type_usable)
{
	if (msg_type_usable) nas->msg_type = nas_msg->msg_type;
	nas->mm_cause    = nas_msg->mm_cause;
	nas->reg_type    = nas_msg->reg_type;
	nas->id_type     = nas_msg->id_type;
	nas->switch_off  = nas_msg->switch_off;
	nas->has_stmsi48 = nas_msg->has_stmsi48;
	nas->stmsi48     = nas_msg->stmsi48;
	/* has_sec_alg 가 거짓이면 libnas 의 두 칸은 뜻이 없음 — 0 이 NEA0, NIA0 라는 정당한 값이라
	 * 센티널만으로는 '골랐음' 과 '안 읽었음' 을 가릴 수 없음(nas.h) */
	if (nas_msg->has_sec_alg) {
		nas->smc_ciph_alg  = nas_msg->nas_ciph_alg;
		nas->smc_integ_alg = nas_msg->nas_integ_alg;
	}
	nas->inner_readable = nas_msg->inner_readable;
}

// tr_nr_cgi_from: libap 의 struct nr_cgi 를 이벤트가 쓰는 struct tr_nr_cgi 로 옮김. 뜻은 같고 이름만 다름
static struct tr_nr_cgi tr_nr_cgi_from(const struct nr_cgi *nr_cgi)
{
	struct tr_nr_cgi tr_nr_cgi = { .cell_id = nr_cgi->nr_cell_identity, .valid = nr_cgi->is_valid };
	memcpy(tr_nr_cgi.plmn_bytes, nr_cgi->plmn_identity, sizeof tr_nr_cgi.plmn_bytes);
	return tr_nr_cgi;
}

// ---- RRC 컨테이너 하나 처리 -> 이벤트 ---------------------------------------------------
static void handle_rrc_container(struct obs *obs, const struct sctp_message *sctp_message, const struct f1ap_msg *f1ap_msg,
								 struct obs_ue_state *ue_state, enum tr_direction direction, const struct f1ap_rrc_container *rrc_container)
{
	// IE 241 은 망 공유용 RRCSetupComplete 인데 CU 가 무시함(f1ap_cu_impl.cpp:358). IE 128 은 DU 가 만든
	//  CellGroupConfig 라 RRC 메시지가 아님. 둘 다 버리지만 이유마다 따로 셈
	//  세는 이유: 안 세면 "DU 가 안 보냈음" 와 같은 모양이 되어 지표에서 가릴 수 없음
	if (rrc_container->ie_id == F1AP_IE_ID_RRC_CONTAINER_RRC_SETUP_COMPLETE) {
		obs->stats.cu_ignored_container_count++;
		return;
	}
	if (rrc_container->ie_id != F1AP_IE_ID_RRC_CONTAINER) {
		obs->stats.non_rrc_container_count++;
		return;
	}
	// 채널과 바이트 모양은 librrc 가 정함. 컨테이너 바이트에 적혀 있지 않고 F1AP 절차, IE 번호, SRB ID 로 정해짐
	//  NONE 은 규칙 표에 없는 조합(SRB ID 없음, 범위 밖, 모르는 절차). 짐작하지 않고 세고 버림
	struct rrc_container_kind container_kind = rrc_kind_for_f1ap(f1ap_msg, rrc_container);
	if (container_kind.channel == RRC_CHANNEL_NONE) {
		obs->stats.unknown_rrc_channel_count++;
		return;
	}
	bool has_pdcp_header = container_kind.encapsulation == RRC_ENCAPSULATION_PDCP;
	bool is_dcch = container_kind.channel == RRC_CHANNEL_UL_DCCH || container_kind.channel == RRC_CHANNEL_DL_DCCH;

	// DCCH 인데 암호 상태면 풀지 않고 OPAQUE 로 올림
	if (is_dcch && has_pdcp_header && !dcch_visible(ue_state, direction)) {
		/* 재수립 grant 만 평문 예외. RRCReestablishment 는 TS 38.331 §5.3.7.4 상 integrity-only 로 보내므로
		 * (암호화를 적용하기 전) 암호 알고리즘과 무관하게 평문이고, 정상 가독임. 그런데 재수립 레코드는
		 * 수립 SMC 를 승계하지 못해 ciph_alg=-1, rrc_sec_state=NONE 이라 관문이 전부 닫혀 평문 grant 까지
		 * OPAQUE 로 떨어졌고, 그 탓에 재수립 성공 카운팅이 암호 세션에서 전부 누락됐음(실측 0/5).
		 *
		 *   요청(CCCH) --> [재활성 창] --첫 하행 1개--> 시험 디코드 --RRCReestablishment 면--> 통과
		 *                                             그 외, 그리고 이후 하행 ------------------> OPAQUE
		 *
		 * 시험은 재활성 창의 첫 하행 한 개뿐이고, 디코드해서 정확히 RRCReestablishment 일 때만 통과시킴.
		 * 그래서 거짓 가독이 날 수 있는 곳이 '요청 직후 첫 하행 한 곳' 으로 묶임. 암호 Complete 는 상행이라
		 * 이 예외 밖이고 계속 닫혀 있음.
		 *
		 * 예외를 보안 전 재수립 레코드로만 한정하는 이유: 실제 단말이 시작한 재수립은 INITIAL UL 이 레코드를
		 * 갈아 치워 connected=0, rrc_sec_state=NONE, ciph_alg=-1 로 들어오므로 이 조건을 통과함. 반대로 AS 보안이
		 * 활성인 암호 단말에 CCCH 재수립 요청을 주입해 reest_reactivated 를 켜도, 그 단말의 첫 하행(암호문)을
		 * 평문 grant 로 시험하지 않음. */
		bool grant_exempt = false;
		if (direction == TR_DIRECTION_DOWN && ue_state->reest_reactivated && !ue_state->reest_grant_seen &&
			!ue_state->connected && ue_state->rrc_sec_state == TR_SEC_NONE && ue_state->ciph_alg < 0) {
			ue_state->reest_grant_seen = true;   // 첫 하행 한 번만 시험. 성공과 실패를 가리지 않음
			struct rrc_msg grant_probe;
			/* 이름만 보면 암호문이 RRCReestablishment 로 약 2.3% 거짓 판독됨 — UPER 가 남는 비트를 관대하게
			 * 다루기 때문임. 실제 grant 는 RRC 페이로드가 2바이트 남짓이라 남는 비트가 8 미만인데, 긴 암호문은
			 * 여분 바이트가 그대로 남음. 그 조건을 같이 요구해 거짓 판독을 줄임. */
			grant_exempt = rrc_parse(container_kind, rrc_container->data, rrc_container->len, &grant_probe) == RRC_OK
						&& grant_probe.msg_name && !strcmp(grant_probe.msg_name, "RRCReestablishment")
						&& grant_probe.trailing_bits < 8;   // 남는 비트가 8 이상이면 긴 암호문임
			rrc_release(&grant_probe);   // 실패했으면 opaque 가 NULL 이라 아무 일도 하지 않음(rrc.h 계약)
		}
		if (!grant_exempt) {
			struct obs_event event; fill_event_header(&event, obs, sctp_message, TR_EVENT_RRC_DCCH_OPAQUE, direction); fill_f1ue(&event, ue_state);
			event.quality = TR_QUALITY_UNKNOWN; event.payload.dcch_opaque.srb_id = rrc_container->srb_id;
			emit(obs, &event);
			return;
		}
		// 통과했으면 아래 정상 디코드 경로로 내려가 TR_EVENT_RRC_REEST 를 냄
	}

	// CMD_SENT 의 상행을 카운팅. 첫 상행(SecurityModeComplete 기대) 뒤에는 위 관문이 닫힘
	if (direction == TR_DIRECTION_UP && is_dcch && has_pdcp_header && ue_state->rrc_sec_state == TR_SEC_CMD_SENT && ue_state->ul_dcch_sec_cmd_sent_count < 255)
		ue_state->ul_dcch_sec_cmd_sent_count++;

	struct rrc_msg rrc_msg;
	int parse_result = rrc_parse(container_kind, rrc_container->data, rrc_container->len, &rrc_msg);

	/* 연결 뒤 rrc_sec_state 가 NONE 인 채로 오는 DCCH 를 카운팅해 거짓 가독을 상한에 묶음.
	 * 평문으로 반복되는 것이 정상인 NAS 운반은 상한까지 면제함 — 면제가 없으면 두 번째 NAS 에서 관문이
	 * 닫혀 정작 알고리즘을 실은 AS SecurityModeCommand 가 OPAQUE 가 되고, 그 파급으로 NEA0 정상 해제의
	 * RRCRelease 까지 가려져 suspend 로 오판됐음.
	 * 잔여: 암호문이 우연히 NAS 를 품은 DLInformationTransfer 로 풀리면 면제됨(매우 드묾). */
	if (direction == TR_DIRECTION_DOWN && is_dcch && has_pdcp_header && ue_state->connected && ue_state->rrc_sec_state == TR_SEC_NONE && ue_state->dl_dcch_sec_none_count < 255) {
		/* DLInformationTransfer 는 메시지 종류로만 가름. dedicatedNAS 는 선택 IE 라 없어도 정상이고, NAS 유무를
		 * 조건에 걸면 NAS 없는 정상 DLInformationTransfer 가 세어져 다음 SMC 가 가려짐. */
		bool dlinfo = (parse_result == 0 && rrc_msg.msg_name && !strcmp(rrc_msg.msg_name, "DLInformationTransfer"));
		if (dlinfo && ue_state->dl_dlinfo_exempt_count < obs->obs_cfg.dl_dcch_exempt_max_count) ue_state->dl_dlinfo_exempt_count++;
		else { if (dlinfo) obs->stats.dcch_gate_closed_on_cap_count++; ue_state->dl_dcch_sec_none_count++; }   // 깨끗한 NAS 운반이 상한에 걸려 닫힘 = 인증이 길었을 가능성
	}
	/* 하행과 같게 상행도 묶음. 하행 SMC 와 상행 SMComplete 를 둘 다 놓쳐 rrc_sec_state 가 NONE 에 고착됐을
	 * 때, 상행 암호문이 평문으로 읽혀 가짜 이벤트와 가짜 malformed 를 내던 것을 막음. */
	if (direction == TR_DIRECTION_UP && is_dcch && has_pdcp_header && ue_state->connected && ue_state->rrc_sec_state == TR_SEC_NONE && ue_state->ul_dcch_sec_none_count < 255) {
		bool is_ul_information_transfer = (parse_result == 0 && rrc_msg.msg_name && !strcmp(rrc_msg.msg_name, "ULInformationTransfer"));
		if (is_ul_information_transfer && ue_state->ul_dlinfo_exempt_count < obs->obs_cfg.dl_dcch_exempt_max_count) ue_state->ul_dlinfo_exempt_count++;
		else { if (is_ul_information_transfer) obs->stats.dcch_gate_closed_on_cap_count++; ue_state->ul_dcch_sec_none_count++; }
	}

	if (parse_result != 0) {
		/* 가시 구간(보안 전이나 CCCH)의 RRC 디코드 실패는 규격 비적합임. reason 으로 가름 — -EBADMSG 는
		 * 구조가 깨진 것, -ENOMSG 는 이름이 없는 것(릴리스 차이일 수 있음). 엔벨로프는 풀렸으므로 누가
		 * 보냈는지 알 수 있어 단말 단위로 올림. */
		struct obs_event event; fill_event_header(&event, obs, sctp_message, TR_EVENT_RRC_MALFORMED, direction); fill_f1ue(&event, ue_state);
		event.quality = TR_QUALITY_UNKNOWN; event.payload.malformed.reason = parse_result; emit(obs, &event);
		rrc_release(&rrc_msg); return;
	}
	enum tr_event_kind kind = rrc_kind(&rrc_msg);
	struct obs_event event; fill_event_header(&event, obs, sctp_message, kind, direction); fill_f1ue(&event, ue_state);
	// 실제로 푼 채널과 ASN.1 타입 이름을 이벤트에 실음. 이름은 librrc 의 고정 문자열이라 rrc_release 뒤에도 유효
	event.rrc_chan = (int16_t)rrc_msg.channel;
	event.rrc_msg_name = rrc_msg.msg_name;

	switch (kind) {
	case TR_EVENT_RRC_SETUP_REQUEST:
		// librrc 의 갈래를 우리 열거로 옮김. 번호가 같아도 캐스트로 두지 않음 - librrc 가 갈래를 늘리면
		//  캐스트는 조용히 틀리고, default 없는 switch 는 컴파일이 알려 줌
		switch (rrc_msg.ue_identity_type) {
		case RRC_UE_IDENTITY_NG_5G_S_TMSI_PART1:
			event.payload.setup_request.ue_identity_type = TR_UE_IDENTITY_STMSI_PART1;
			break;
		case RRC_UE_IDENTITY_RANDOM_VALUE:
			event.payload.setup_request.ue_identity_type = TR_UE_IDENTITY_RANDOM;
			break;
		case RRC_UE_IDENTITY_NONE:
			event.payload.setup_request.ue_identity_type = TR_UE_IDENTITY_NONE;
			break;
		}
		event.payload.setup_request.ue_identity39 = rrc_msg.ue_identity;
		event.payload.setup_request.est_cause = rrc_msg.establishment_cause.value;
		event.payload.setup_request.crnti = f1ap_msg->has_crnti ? f1ap_msg->crnti : ue_state->crnti;
		if (f1ap_msg->has_crnti) { ue_state->crnti = f1ap_msg->crnti; ue_state->has_crnti = true; }
		ue_state->est_cause = rrc_msg.establishment_cause.value;   // 매칭 키용. 재수립과 재개 폴백은 원인이 없어 corr_on_f1 이 CORR_EST_CAUSE_ANY 로 등록함
		break;
	case TR_EVENT_RRC_REEST_REQUEST:
		event.payload.reest_request.old_crnti = rrc_msg.old_crnti;
		event.payload.reest_request.old_pci = rrc_msg.old_pci;
		event.payload.reest_request.reest_cause = rrc_msg.reestablishment_cause.value;
		event.payload.reest_request.crnti = f1ap_msg->has_crnti ? f1ap_msg->crnti : ue_state->crnti;
		ue_state->prior_req = TR_PRIOR_REEST_FALLBACK;   // 폴백 RRCSetup 이나 RRCReject 가 어느 요청에서 왔는지 가릴 수 있게 함
		ue_state->reest_reactivated = true;   // 재수립도 저장 보안을 재활성시킴. 암호 Complete 이후는 fail-closed(resumed 와 대칭)
		ue_state->reest_grant_seen = false;   // 재수립마다 grant 시험을 한 번 되살림. 레코드가 재사용될 수 있어서임
		break;
	case TR_EVENT_RRC_RESUME_REQUEST:
		event.payload.resume_request.i_rnti = rrc_msg.resume_i_rnti; event.payload.resume_request.i_rnti_is_full40 = rrc_msg.is_full_resume_i_rnti;
		event.payload.resume_request.resume_cause = rrc_msg.resume_cause.value;
		event.payload.resume_request.ccch1 = container_kind.channel == RRC_CHANNEL_UL_CCCH1;
		ue_state->prior_req = TR_PRIOR_RESUME_FALLBACK;
		ue_state->resumed = true;   // 재개 레코드 표시. 이후 암호 DCCH 는 fail-closed
		break;
	case TR_EVENT_RRC_SETUP:
		/* 재개에서 수립으로 폴백한 것(TS 38.331 §5.3.13, gNB 재시작이나 INACTIVE 컨텍스트 만료 뒤에 흔함).
		 * RRCSetup 이나 RRCReject 가 RRCResumeRequest 의 응답으로 오면 폴백이 확정이므로 resumed 를 내려야
		 * 뒤따르는 평문 SetupComplete 와 SMC 가 보임. 안 내리면 그 단말이 영구 OPAQUE 가 됨.
		 * 허가된 재개는 RRCResume(DCCH)으로 오지 RRCSetup 이나 RRCReject 가 아니므로, 그 경로에서는
		 * resumed 가 유지돼 정상 fail-closed 임. */
		event.payload.setup.prior_req = ue_state->prior_req;
		ue_state->resumed = false;
		ue_state->reest_reactivated = false;
		break;
	case TR_EVENT_RRC_REJECT:
		event.payload.reject.wait_time_s = rrc_msg.wait_time_s;
		event.payload.reject.prior_req = ue_state->prior_req;
		ue_state->resumed = false;
		ue_state->reest_reactivated = false;
		break;
	case TR_EVENT_RRC_SETUP_COMPLETE:
		event.payload.setup_complete.has_stmsi48 = rrc_msg.has_s_tmsi; event.payload.setup_complete.stmsi48 = rrc_msg.s_tmsi;
		event.payload.setup_complete.has_stmsi_part2 = rrc_msg.has_s_tmsi_part2; event.payload.setup_complete.stmsi_part2 = rrc_msg.s_tmsi_part2;
		nas_values_init(&event.payload.setup_complete.nas);
		if (rrc_msg.nas_pdu_count > 0) {
			/* 초기 NAS(REGISTRATION REQUEST, SERVICE REQUEST)는 AS 보안 전 SRB1 평문이라 F1 에서 바로 읽힘.
			 * 보안 전이므로 nas_ciph_alg 와 무관함(SHT 0 평문). 보안 뒤의 F1 NAS 는 쓰지 않음 — 그쪽은 N2 임. */
			struct nas_msg nas_msg;
			int parse_result = nas_parse(rrc_msg.nas_pdus[0].data, rrc_msg.nas_pdus[0].len, NAS_CIPH_UNKNOWN, &nas_msg);
			// RRCSetupComplete 는 UE→CU 뿐이므로 방향은 상행 고정임
			bool msg_type_usable = nas_accept_result(obs, &nas_msg, TR_DIRECTION_UP);
			/* 실패 경로에서도 epd, sht 는 읽은 만큼 담음 — libnas 가 음수 반환에도 그 둘은 유효하다고
			 * 계약했고, N2 자리도 같게 함. 한쪽만 버리면 같은 사실이 호출 지점마다 다르게 보임. */
			event.payload.setup_complete.nas.epd = nas_msg.epd;
			event.payload.setup_complete.nas.sht = nas_msg.sht;
			event.payload.setup_complete.nas.parse_ok = (parse_result == 0);
			if (parse_result == 0) {
				nas_values_take(&event.payload.setup_complete.nas, &nas_msg, msg_type_usable);
				/* 방향이 상행으로 고정이므로 SHT 3 은 규격상 올 수 없음(표 9.3.1 NOTE 1 과 §8.2.25.1).
				 * SMC 모양 NAS(has_sec_alg)도 같은 이유로 단말이 만든 것임. 학습은 애초에 하지 않는 곳임. */
				if (nas_msg.sht == 3) {
					obs->stats.nas_sec_header_direction_mismatch_count++;
					event.payload.setup_complete.nas.sec_header_direction_ok = false;
				}
				if (nas_msg.has_sec_alg) obs->stats.nas_smc_learn_skipped_count++;
			} else {
				obs->stats.nas_malformed_count++;
			}
		}
		/* 이 대입은 위의 거짓 가독 카운팅 블록과 관문 검사 뒤에 있어야 함. 위로 올리면 SetupComplete 자신이
		 * 예산을 써서 바로 다음의 정상 NAS 운반을 OPAQUE 로 막음(정상 흐름을 오탐). 옮기지 말 것. */
		ue_state->connected = true;
		// 첫 NAS 와 셀과 원인으로 F1 항목을 등록해 N2 INITIAL UE MESSAGE 와 매칭함
		if (rrc_msg.nas_pdu_count > 0) {
			bool fallback_without_cause = ue_state->prior_req == TR_PRIOR_REEST_FALLBACK || ue_state->prior_req == TR_PRIOR_RESUME_FALLBACK;
			corr_on_f1(obs, &ue_state->cell, ue_state->est_cause, fallback_without_cause, rrc_msg.nas_pdus[0].data, (uint32_t)rrc_msg.nas_pdus[0].len, event.wallclock_ns,
					   ue_state->assoc_id, ue_state->du_ue_id, ue_state->record_id);
		}
		break;
	case TR_EVENT_RRC_SMC:
		event.payload.smc.ciph_alg = rrc_msg.ciphering_algorithm.value; event.payload.smc.integ_alg = rrc_msg.integrity_algorithm.value;
		ue_state->rrc_sec_state = TR_SEC_CMD_SENT; ue_state->ciph_alg = rrc_msg.ciphering_algorithm.value;   // 고른 알고리즘을 기록. 관문이 이 값으로 가독을 판정함
		break;
	case TR_EVENT_RRC_SMC_COMPLETE:
		ue_state->rrc_sec_state = TR_SEC_ACTIVE;
		break;   // 이후 DCCH 는 ciph_alg 로 관문
	case TR_EVENT_RRC_SMC_FAILURE:
		/* SecurityModeFailure 는 AS 보안 활성 실패임(TS 33.501, TS 38.331 §5.3.4.3). 단말은 SMC 이전 상태로
		 * 계속하므로, 수립 SMC 라면 평문으로 돌아감. CMD_SENT 를 유지하면 뒤따르는 평문 신호가 거짓 OPAQUE
		 * 로 떨어지고, ciph_alg 를 유지하면 '활성 암호' 를 허위로 주장함. 그래서 NONE 으로 되돌림.
		 * 예산 칸 셋도 같이 0 으로 되돌림. 안 되돌리면 첫 SMC 가 올려둔 dl_dcch_sec_none_count 가 남아 재시도
		 * SMC(하행)가 OPAQUE 로 막히고, 설령 올라가도 ul_dcch_sec_cmd_sent_count 가 재시도 SMComplete(상행)를
		 * 막아 rrc_sec_state 가 CMD_SENT 나 NONE 에 영구 고착됨. 실패 자체가 관측된 평문 사건이므로 보안 전
		 * 예산으로 되돌리는 것이 맞음 — 재시도 SMC 교환 한 번만 다시 허용하고 그 뒤로는 다시 묶임. */
		ue_state->rrc_sec_state = TR_SEC_NONE; ue_state->ciph_alg = -1;
		ue_state->dl_dcch_sec_none_count = 0; ue_state->ul_dcch_sec_none_count = 0; ue_state->ul_dcch_sec_cmd_sent_count = 0;
		break;
	case TR_EVENT_RRC_REEST:
		break;   // 값 칸 없음. 재수립 grant 자체가 신호임
	case TR_EVENT_RRC_REEST_COMPLETE:
		ue_state->connected = true;
		break;
	case TR_EVENT_RRC_RELEASE:
		// RRCRelease 를 푼 뒤라 suspendConfig 유무가 확정임. UNKNOWN 은 관문이 닫혀 풀지 못한 경로에서만 나옴
		event.payload.release.suspend = rrc_msg.has_suspend_config ? TR_SUSPEND_YES : TR_SUSPEND_NO;
		event.payload.release.after_sec = (ue_state->rrc_sec_state == TR_SEC_ACTIVE);
		break;
	case TR_EVENT_RRC_RECONFIG_SEC:
		if (rrc_msg.ciphering_algorithm.value < 0 && rrc_msg.integrity_algorithm.value < 0) kind = TR_EVENT_RRC_OTHER;   // securityConfig 가 없으면 OTHER 로
		event.kind = kind;
		if (kind == TR_EVENT_RRC_RECONFIG_SEC) {
			event.payload.smc.ciph_alg = rrc_msg.ciphering_algorithm.value; event.payload.smc.integ_alg = rrc_msg.integrity_algorithm.value;
			/* 세션 중 재키잉(RRCReconfiguration 의 securityConfig)이 알고리즘을 바꾸면 관문이 쓰는 ciph_alg 도
			 * 갱신해야 함. 안 하면 수립이 NEA0 였다가 실제 암호로 재키된 뒤에도 관문이 계속 평문으로 열려
			 * 거짓 가독이 상한 없이 남음. NEA0 에서 NEAx 로 바뀌는 것은 드물지만 fail-closed 원칙상 추적함. */
			if (rrc_msg.ciphering_algorithm.value >= 0) ue_state->ciph_alg = rrc_msg.ciphering_algorithm.value;
		}
		else { event.payload.rrc_other.rrc_chan = container_kind.channel; event.payload.rrc_other.rrc_msg_name = rrc_msg.msg_name; }
		break;
	default:   // TR_EVENT_RRC_OTHER, TR_EVENT_RRC_RESUME, TR_EVENT_RRC_RESUME_COMPLETE 등
		if (kind == TR_EVENT_RRC_OTHER) { event.payload.rrc_other.rrc_chan = container_kind.channel; event.payload.rrc_other.rrc_msg_name = rrc_msg.msg_name; }
		break;
	}
	emit(obs, &event);
	rrc_release(&rrc_msg);
}

// ---- F1AP 메시지 하나 처리 --------------------------------------------------------------
static void teardown_assoc(struct obs *obs, uint32_t assoc_id, uint64_t end_ns);   // 전방선언. obs_on_assoc 과 같이 씀

/* RESET_UE_MAX: 일부 RESET 한 건에서 들고 올라가는 UE 항목의 상한.
 *   TS 38.473 의 maxnoofIndividualF1ConnectionsToReset 은 65536 이지만, 그만큼을 알림 한 줄에 실으면
 *   JSON 이 수백 KB 가 됨. 넘친 항목은 목록에서 빼고 세므로 읽는 쪽은 그만큼 덜 닫음 —
 *   이 상한은 '정확히 가리킬 수 있는 범위' 만 정하고, 넘친 사실은 ue_overflow_count 로 남음. */
#define RESET_UE_MAX 256

/* assoc_fill_cells: 재시작 알림에 그 DU 의 셀 목록을 실음.
 *   이유: RESET 메시지에는 셀이 없고 SETUP 의 셀 목록도 그 메시지에만 있으므로, 연결에 기억해 둔 것을 꺼냄.
 *   빌려 쓰는 포인터 — 콜백이 돌아가는 동안만 유효. 모르면 cells_known 을 거짓으로 둬 읽는 쪽이
 *   '모든 셀' 로 보게 함(목록을 지어내지 않음). */
static void assoc_fill_cells(const struct obs_assoc_record *assoc_record, struct obs_event *event)
{
	if (!assoc_record || assoc_record->cell_count == 0 || assoc_record->cell_overflow)
		return;
	event->payload.reset.cells = assoc_record->cells;
	event->payload.reset.cell_count = assoc_record->cell_count;
	event->payload.reset.cells_known = true;
}
/* f1_reset_all: 한 연결의 F1 단말 레코드를 전부 지움(이벤트는 내지 않음).
 *   이유: F1 RESET(전체)과 F1 SETUP 은 둘 다 그 인터페이스의 단말 컨텍스트를 한꺼번에 없앰
 *     — TS 38.473 §8.2.1.2.1 "remove the indicated UE contexts",
 *       §8.2.3.1 "re-initialises the F1AP UE-related contexts (if any) … like a Reset procedure would do".
 *     우리 표에 남겨 두면 다음 단말이 같은 du_ue_id 로 올 때 옛 레코드의 AS 보안 상태로 가시성 관문을
 *     판정하고(조용한 오값), INITIAL UL 은 UE_REPLACED 로 떨어져 du_id_reuse_count 가 우리 표 탓에 오름.
 *   이탈 이벤트를 내지 않는 이유: 집계 쪽은 RESET / SETUP 이벤트 하나로 그 범위를 닫으므로
 *     레코드별 이탈까지 내면 같은 이탈을 두 번 셈. N2 쪽 n2_reset_all 과 같은 처분임.
 *   점유 UE 만 도는 이유는 teardown_assoc 과 같음(전수 배열 스캔은 위조 RESET 으로 스톨을 만들 수 있음). */
static void f1_reset_all(struct obs *obs, uint32_t assoc_id)
{
	for (int i = obs->lru_head; i >= 0; ) {
		int next_index = obs->ue_states[i].lru_next;
		if (obs->ue_states[i].used && obs->ue_states[i].assoc_id == assoc_id) {
			ue_remove(obs, i);
			obs->stats.f1_reset_removed_count++;
		}
		i = next_index;
	}
}

/* handle_f1ap: F1AP 메시지 하나를 이벤트로 바꿈. 처리 순서가 곧 의미임 — 연결 수준 절차는 거기서
 *   끝나고, 단말 수준 절차만 아래로 내려가 레코드를 만지고 RRC 컨테이너를 품.
 *
 *     방향 판정 --> 연결 수준 절차 --여기서 끝남--> return
 *               --> 단말 수준 절차 --> 레코드 찾기, 생성 --> 절차별 이벤트 --> RRC 컨테이너 루프
 *
 *     연결 수준   F1 SETUP            셀 집합을 갈아치우고 재시작을 알림. 가린 판이면 우리 표도 비움
 *                 GNB-DU CFG UPDATE   셀을 더하기만 함
 *                 RESET               범위가 전체면 그 연결의 표를 비우고, 일부면 가리킨 단말만
 *     단말 수준   INITIAL UL          레코드 생성. 같은 번호가 또 오면 옛 레코드를 닫고 새로 만듦
 *                 UE CTX SETUP        결과 세 갈래(요청, 성공, 실패)를 그대로 옮김
 *                 UE CTX RELEASE      COMMAND 는 유예 표시만 하고, COMPLETE 에서 레코드를 지움
 *                 그 밖               레코드만 갱신하고 RRC 컨테이너 루프로
 *
 *   부작용: 이벤트 방출, obs->stats 갱신, 단말 표와 연결 레코드 변경. */
static void handle_f1ap(struct obs *obs, const struct sctp_message *sctp_message, const struct f1ap_msg *f1ap_msg)
{
	/* 방향은 절차와 PDU 종류로 먼저 정함 — 그 짝은 규격이 정의한 것이라 정확함. 정해지지 않으면
	 * 와이어의 IANA 포트 규칙으로 가고, 그래도 모르면 미상으로 두고 카운팅함.
	 * 절차 코드만 보고 통째로 정하면 안 되는 이유: 같은 절차의 RESPONSE 와 COMPLETE 는 반대 방향이고,
	 * UEContextModificationConfirm 은 CU 에서 DU 로 가면서 RRC 컨테이너를 품음. 그것을 상행으로 잘못
	 * 실으면 아래 컨테이너 루프가 하행 메시지로 상행 평문 예산을 깎음. */
	enum tr_direction direction = decide_direction(obs, sctp_message->record, TR_IFACE_F1,
									   f1ap_proc_direction(f1ap_msg->procedure_code, f1ap_msg->pdu_type));
	/* 문법에 없는 (절차, PDU 종류) 짝과 F1AP-PDU 의 확장 선택지는 여기 오지 않음 — f1ap_parse 가
	 *   F1AP_UNKNOWN_MESSAGE 를 돌려주고 obs_on_sctp 가 ap_body_unknown_count 로 카운팅함. 그래서 7바이트
	 *   쓰레기가 F1 RESET(전체) 이벤트가 되어 그 연결의 단말을 전부 지우는 일이 없음. */

	// F1 SETUP 이 가리키는 F1-C 인스턴스를 못 가린 판. 범위를 추측하지 않고 카운팅함
	bool f1_setup_ambiguous = f1ap_msg->procedure_code == P_F1_SETUP && !f1ap_msg->has_du_id;

	// 연결에서 DU 로 가는 매핑 학습. F1 SETUP 과 GNB-DU CONFIGURATION UPDATE 의 gNB-DU ID
	if (f1ap_msg->has_du_id && (f1ap_msg->procedure_code == P_F1_SETUP || f1ap_msg->procedure_code == P_GNBDU_CFG_UPD)) {
		/* 같은 gNB-DU ID 를 든 다른 연결은 재시작으로 죽은 옛 연결임. F1 SETUP 은 F1 인터페이스의
		 * (재)초기화이므로(TS 38.473 §8.2.3) 그 도착을 신호로 삼아 옛 연결을 정리함.
		 * 왜 필요한가: DU 가 새 소스 포트로 재접속하면 SCTP 재시작 탐지가 같은 4-tuple 만 보므로 놓치고,
		 * 옛 연결이 END 없이 남음. 연결된 단말은 TTL 면제이고 LRU 는 개수로만 밀려나므로, 상시 집계되는
		 * 평균과 최대 연결 수가 무기한 과대 계수됨(처닝이 적은 사설 5G 에서는 사실상 영구).
		 * 시간 초과로 추측하지 않고 관측 가능한 신호에 근거함 — F1-U 만 쓰는 긴 세션을 잘못 떨어뜨리지
		 * 않음. 재접속이 아예 없는 조용한 죽음은 수동 관측으로는 볼 수 없음. */
		if (f1ap_msg->procedure_code == P_F1_SETUP)
			for (uint32_t i = 0; i < obs->assoc_capacity; i++)
				if (obs->assoc_records[i].used && obs->assoc_records[i].has_du_id && obs->assoc_records[i].du_id == f1ap_msg->du_id && obs->assoc_records[i].assoc_id != sctp_message->assoc_id)
					teardown_assoc(obs, obs->assoc_records[i].assoc_id, sctp_message->record ? sctp_message->record->capture_time_ns : obs->now_ns);
		struct obs_assoc_record *assoc_record = assoc_get(obs, sctp_message->assoc_id);
		if (assoc_record) {
			/* 같은 연결에 다른 gNB-DU ID 의 F1 SETUP = 공유 TNL(§8.2.3.1 NOTE: "several F1 Setup procedures
			 *   may be issued via the same TNL association"). 그 연결의 단말이 어느 인스턴스 것인지 우리
			 *   색인((연결, DU 번호))으로는 못 가르므로 닫을 범위를 정하지 않음. 종전엔 조용히 덮어썼음. */
			if (f1ap_msg->procedure_code == P_F1_SETUP && assoc_record->has_du_id && assoc_record->du_id != f1ap_msg->du_id)
				f1_setup_ambiguous = true;
			assoc_record->du_id = f1ap_msg->du_id; assoc_record->has_du_id = true;
		}
	}

	/* F1 SETUP REQUEST 의 Served Cell 을 집계 층의 셀 표에 등록시킴(이벤트가 나르는 값은 NR CGI 뿐).
	 *   f1ap_msg.served_cells 는 F1 SETUP REQUEST 의 NR CGI 만 담으므로(ap.h), GNB-DU CONFIGURATION UPDATE 로
	 *   추가되거나 바뀐 셀은 이 층에서 나오지 않음(served_cell_count 가 0). */
	if (f1ap_msg->procedure_code == P_F1_SETUP || f1ap_msg->procedure_code == P_GNBDU_CFG_UPD) {
		struct obs_assoc_record *assoc_record = assoc_get(obs, sctp_message->assoc_id);
		// F1 SETUP 은 인터페이스 재초기화라 셀 집합을 갈아치우고, CONFIGURATION UPDATE 는 더함
		if (assoc_record && f1ap_msg->procedure_code == P_F1_SETUP && f1ap_msg->pdu_type == F1AP_PDU_INITIATING) {
			assoc_record->cell_count = 0;
			assoc_record->cell_overflow = false;
		}
		for (int item_index = 0; item_index < f1ap_msg->served_cell_count; item_index++) {
			struct obs_event event; fill_event_header(&event, obs, sctp_message, TR_EVENT_F1_CELL_CONFIG, TR_DIRECTION_UP);
			event.cell = tr_nr_cgi_from(&f1ap_msg->served_cells[item_index]);
			emit(obs, &event);
			if (!assoc_record)
				continue;
			if (assoc_record->cell_count == ASSOC_CELL_MAX) { assoc_record->cell_overflow = true; continue; }
			assoc_record->cells[assoc_record->cell_count++] = event.cell;
		}
		/* 재시작 알림: DU 가 F1 을 새로 맺었음 = 그 DU 의 단말 컨텍스트가 단말별 해제 줄 없이 한꺼번에
		 *   사라졌음. REQUEST 만 냄 — RESPONSE 와 FAILURE 는 CU 가 보내는 답이라 재시작 시점이 아님.
		 *
		 *   닫을 범위는 SCTP 연결이 아니라 F1-C 인스턴스이고 그것을 가리키는 것이 gNB-DU ID 임(§8.2.3.1 NOTE).
		 *     인스턴스를 가린 판   scope=ALL   연결 전체를 닫음. 우리 표도 비움
		 *     못 가린 판(공유 TNL) scope=LIST  목록이 비어 '닫을 것 없음'. 셀 목록은 이 메시지의 것이라
		 *                                      그대로 싣고, 못 가렸다는 사실은 계수기로 남김 */
		if (f1ap_msg->procedure_code == P_F1_SETUP && f1ap_msg->pdu_type == F1AP_PDU_INITIATING) {
			struct obs_event event; fill_event_header(&event, obs, sctp_message, TR_EVENT_F1_SETUP, direction);
			event.payload.reset.scope = f1_setup_ambiguous ? TR_SCOPE_LIST : TR_SCOPE_ALL;
			assoc_fill_cells(assoc_record, &event);
			emit(obs, &event);
			if (f1_setup_ambiguous)
				obs->stats.f1_setup_ambiguous_count++;
			else
				f1_reset_all(obs, sctp_message->assoc_id);
		}
		if (f1ap_msg->procedure_code == P_F1_SETUP) return;
	}
	if (f1ap_msg->procedure_code == P_GNBDU_CFG_UPD) return;   // 셀만 읽는 메시지임. 단말 수준 처리로 내려보내지 않음

	if (f1ap_msg->procedure_code == P_RESET) {
		// RESET ACKNOWLEDGE 에는 ResetType 이 없어 범위가 0 으로 읽힘. 요청만 이벤트로 냄
		if (f1ap_msg->pdu_type != F1AP_PDU_INITIATING) return;
		struct obs_event event; fill_event_header(&event, obs, sctp_message, TR_EVENT_F1_RESET, direction);
		// 범위를 모르는 RESET(확장 갈래, 모르는 ResetAll 값)은 전체로 실음
		event.payload.reset.scope = (f1ap_msg->reset_type == RESET_TYPE_PART) ? TR_SCOPE_LIST : TR_SCOPE_ALL;
		assoc_fill_cells(assoc_get(obs, sctp_message->assoc_id), &event);
		/* 일부 RESET 의 단말 번호. 두 번호 모두 선택 필드라(ap.h) DU 쪽 번호가 없는 항목이 있을 수 있고,
		 *   그런 항목은 가리킬 방법이 없으므로 목록에서 빼고 따로 카운팅함. 읽는 쪽은 센 만큼 덜 닫음 —
		 *   가리키지 못한 단말을 '전체' 로 넓히면 멀쩡한 단말까지 닫힘(확신 있는 오값). */
		struct tr_reset_ue reset_ues[RESET_UE_MAX];
		if (event.payload.reset.scope == TR_SCOPE_LIST) {
			for (int item_index = 0; item_index < f1ap_msg->reset_ue_count; item_index++) {
				if (event.payload.reset.ue_count == RESET_UE_MAX) { event.payload.reset.ue_overflow_count++; continue; }
				const struct f1ap_reset_ue *item = &f1ap_msg->reset_ues[item_index];
				struct tr_reset_ue *reset_ue = &reset_ues[event.payload.reset.ue_count++];
				*reset_ue = (struct tr_reset_ue){
					.du_ue_id     = item->du_ue_id,
					.has_du_ue_id = item->has_du_ue_id,
					.cu_ue_id     = item->cu_ue_id,
					.has_cu_ue_id = item->has_cu_ue_id,
				};
				/* 우리 표에서 그 단말을 찾아 키를 같이 올림. CU 번호만 온 항목은 찾을 수 없음 —
				 *   우리 색인이 (연결, DU 번호)뿐이기 때문임. 못 찾으면 f1ue.valid 가 거짓으로 남고,
				 *   읽는 쪽은 그 단말을 닫지 않고 카운팅함(지어내지 않음). */
				int ue_index = item->has_du_ue_id ? ue_find(obs, sctp_message->assoc_id, item->du_ue_id) : -1;
				if (ue_index < 0)
					continue;
				reset_ue->f1ue = f1ue_key_of(&obs->ue_states[ue_index]);
				// 키를 바로 위에서 복사했으므로 지금 지워도 이벤트는 온전함. 지우는 이유는 f1_reset_all 과 같음
				ue_remove(obs, ue_index);
				obs->stats.f1_reset_removed_count++;
			}
			event.payload.reset.ues = reset_ues;
		}
		emit(obs, &event);
		if (event.payload.reset.scope == TR_SCOPE_ALL)
			f1_reset_all(obs, sctp_message->assoc_id);
		return;
	}

	/* 여기부터는 단말 레코드가 있어야 함. DU 번호가 없으면 레코드를 찾을 색인이 없음.
	 *   계수기를 두지 않는 근거: 이 번호가 선택 IE 인 메시지는 UE CONTEXT SETUP 의 REQUEST 와 FAILURE
	 *   둘뿐이고(asn1/f1ap-18.8.0.asn 전수 — 나머지 단말 연관 메시지는 전부 mandatory), 그 둘의 하류
	 *   소비자 두 곳이 다 같은 번호를 필수로 요구함 —
	 *     집계 층: f1ue 키로 찾은 단말 레코드에만 C-RNTI 와 셀을 적음
	 *     출력 층: 단말 이벤트 줄은 cell_id 와 du_ue_id 가 둘 다 있어야 나감
	 *   즉 '못 읽은 것' 이 아니라 '상대가 안 보낸 것' 이고, 보내지 않은 번호로는 아무 소비자도 할 일이
	 *   없음. UECNTX.ConnEstabAtt 는 이 메시지가 아니라 NGAP INITIAL UE MESSAGE 가 세므로
	 *   (TS 28.552 §5.1.1.16.1 c) 지표도 깎이지 않음. */
	if (!f1ap_msg->has_du_ue_id) return;

	// 단말 레코드 찾기와 생성
	int idx = ue_find(obs, sctp_message->assoc_id, f1ap_msg->du_ue_id);
	if (f1ap_msg->procedure_code == P_INITIAL_UL) {
		if (idx >= 0) {   // 같은 (연결, DU 번호)가 다시 나타남 = DU 번호 재사용. 옛 레코드를 닫고 새로 만듦
			struct obs_event event; fill_event_header(&event, obs, sctp_message, TR_EVENT_OBS_UE_REPLACED, direction); fill_f1ue(&event, &obs->ue_states[idx]);
			emit(obs, &event); obs->stats.ue_replaced_count++; obs->stats.du_id_reuse_count++;
			ue_remove(obs, idx);
		}
		idx = ue_create(obs, sctp_message->assoc_id, f1ap_msg->du_ue_id);
		if (idx < 0) return;   // 상한에 걸려 축출도 실패함
		set_f1ue_keys(obs, &obs->ue_states[idx]);
		if (f1ap_msg->nr_cgi.is_valid) obs->ue_states[idx].cell = tr_nr_cgi_from(&f1ap_msg->nr_cgi);
		if (f1ap_msg->has_crnti) { obs->ue_states[idx].crnti = f1ap_msg->crnti; obs->ue_states[idx].has_crnti = true; }
		// 메시지당 한 번. RRC 컨테이너를 못 풀어도 단말 컨텍스트는 생기므로 RRC 이벤트에 얹지 않고 따로 냄
		struct obs_event event; fill_event_header(&event, obs, sctp_message, TR_EVENT_F1_INITIAL_UL, direction);
		fill_f1ue(&event, &obs->ue_states[idx]);
		event.payload.initial_ul.has_du_to_cu_rrc_container = f1ap_msg->has_du_to_cu_rrc_container;
		emit(obs, &event);
	}
	/* 수립을 못 본 단말의 해제(COMMAND 나 COMPLETE)로는 레코드를 만들지 않음. 만들면 없던 단말이 생겨
	 * '수립 없는 종료' 가 집계 층으로 흘러감. N2 쪽도 같게 막아 둠. */
	if (idx < 0 && (f1ap_msg->procedure_code == P_UE_CTX_RELEASE || f1ap_msg->procedure_code == P_ERROR_INDICATION)) return;   // ERROR INDICATION 의 DU 번호는 '모르는 번호' 일 수 있어 레코드를 만들지 않음(Cause 가 unknown-or-already-allocated-gnb-du-ue-f1ap-id)
	if (idx < 0) {
		// INITIAL UL 을 못 본 뒤 등장(late join). 레코드는 만들되 보안 상태가 미상이라 가시성 관문을 닫음
		idx = ue_create(obs, sctp_message->assoc_id, f1ap_msg->du_ue_id);
		if (idx < 0) return;
		set_f1ue_keys(obs, &obs->ue_states[idx]);
		obs->ue_states[idx].late_join = true;
	}
	struct obs_ue_state *ue_state = &obs->ue_states[idx];
	ue_state->last_ns = obs->now_ns; lru_touch(obs, idx);
	if (f1ap_msg->has_cu_ue_id) { ue_state->cu_ue_id = f1ap_msg->cu_ue_id; ue_state->has_cu_ue_id = true; }
	if (f1ap_msg->has_crnti) { ue_state->crnti = f1ap_msg->crnti; ue_state->has_crnti = true; }   // UE CONTEXT MODIFICATION RESPONSE 등에서 C-RNTI 가 옴
	// 셀 추적. f1ap_msg 는 NR CGI IE(111)만 담음. UE CONTEXT SETUP 과 MODIFICATION REQUEST 의 SpCell ID(IE 63)는
	//  담지 않아 그 메시지로는 셀이 갱신되지 않음
	if (f1ap_msg->nr_cgi.is_valid) ue_state->cell = tr_nr_cgi_from(&f1ap_msg->nr_cgi);

	/* IE 47(old gNB-DU UE F1AP ID)은 DL RRC MESSAGE TRANSFER 에서만 단말 연결 이전을 뜻함.
	 * RELEASE COMMAND 의 IE 47 은 뜻이 달라, 해제 이벤트의 has_old_du_ue_id 속성으로만 실음. */
	if (f1ap_msg->procedure_code == P_DL_RRC && f1ap_msg->has_old_du_ue_id) {
		struct obs_event event; fill_event_header(&event, obs, sctp_message, TR_EVENT_F1_UE_TRANSFER, direction); fill_f1ue(&event, ue_state);
		event.payload.ue_transfer.old_du_ue_id = f1ap_msg->old_du_ue_id;
		emit(obs, &event);
	}

	// 절차별 F1AP 수준 이벤트
	switch (f1ap_msg->procedure_code) {
	case P_UE_CTX_SETUP: {
		struct obs_event ctx_setup_event; fill_event_header(&ctx_setup_event, obs, sctp_message, TR_EVENT_F1_UE_CTX_SETUP, direction); fill_f1ue(&ctx_setup_event, ue_state);
		/* 결과 세 갈래를 그대로 옮김. bool 로 줄이면 unsuccessfulOutcome 이 successfulOutcome 과 같은 값이
		 *   되어, 출력이 UEContextSetupFailure 를 "UEContextSetupResponse" 로 내보냄. */
		switch (f1ap_msg->pdu_type) {
		case F1AP_PDU_SUCCESSFUL:
			ctx_setup_event.payload.ue_ctx_setup.outcome = TR_AP_OUTCOME_SUCCESS;
			break;
		case F1AP_PDU_UNSUCCESSFUL:
			ctx_setup_event.payload.ue_ctx_setup.outcome = TR_AP_OUTCOME_FAILURE;
			obs->stats.ue_ctx_setup_failure_cause_dropped_count++;   // Cause IE 를 실을 칸이 없음. 버린 사실만 남김
			break;
		default:
			ctx_setup_event.payload.ue_ctx_setup.outcome = TR_AP_OUTCOME_REQUEST;
			break;
		}
		if (f1ap_msg->has_crnti) { ctx_setup_event.payload.ue_ctx_setup.has_crnti = true; ctx_setup_event.payload.ue_ctx_setup.crnti = f1ap_msg->crnti; }
		emit(obs, &ctx_setup_event);
		/* 알고리즘 변경 기회(DU 간 핸드오버)는 여기서 내지 않음: 판단 근거인 CU to DU RRC Information 의
		 *   확장 IE 119(HandoverPreparationInformation) 유무가 f1ap_msg 에 없음(ap.h) */
		break; }
	case P_UE_CTX_REL_REQ: {
		struct obs_event event; fill_event_header(&event, obs, sctp_message, TR_EVENT_F1_UE_CTX_RELEASE_REQ, direction); fill_f1ue(&event, ue_state);
		event.payload.f1_release.cause_group = f1ap_msg->cause.group; event.payload.f1_release.cause_value = f1ap_msg->cause.value;
		event.payload.f1_release.cause_present = f1ap_msg->cause.is_present;
		event.payload.f1_release.cause_group_name = f1ap_msg->cause.group_name; event.payload.f1_release.cause_value_name = f1ap_msg->cause.value_name;
		emit(obs, &event);
		break; }
	case P_UE_CTX_RELEASE:
		if (f1ap_msg->pdu_type == F1AP_PDU_INITIATING) {   // RELEASE COMMAND
			/* 명령에 실린 평문 RRCRelease 를 해제 명령 이벤트보다 먼저 냄.
			 * 집계 층은 '평문 RRCRelease 가 이미 적용돼 RRC 상태가 CONNECTED 가 아님' 을 전제로, 암호 SRB1
			 * 때문에 suspend 를 못 읽은 경우의 분기를 거름. 명령을 먼저 내면 평문 해제(NEA0 경로)에도 그 분기가
			 * 걸려 거짓 UNKNOWN 줄이나 잘못된 등급이 나감. 암호(NEA2)면 컨테이너가 OPAQUE 라 RRCRelease 가
			 * 안 나가고 명령만 나가므로 그 분기가 제대로 걸림. */
			for (int item_index = 0; item_index < f1ap_msg->rrc_container_count; item_index++)
				handle_rrc_container(obs, sctp_message, f1ap_msg, ue_state, direction, &f1ap_msg->rrc_containers[item_index]);
			struct obs_event event; fill_event_header(&event, obs, sctp_message, TR_EVENT_F1_UE_CTX_RELEASE_CMD, direction); fill_f1ue(&event, ue_state);
			event.payload.f1_release.cause_group = f1ap_msg->cause.group; event.payload.f1_release.cause_value = f1ap_msg->cause.value;
			event.payload.f1_release.cause_present = f1ap_msg->cause.is_present;
			event.payload.f1_release.cause_group_name = f1ap_msg->cause.group_name; event.payload.f1_release.cause_value_name = f1ap_msg->cause.value_name;
			event.payload.f1_release.has_old_du_ue_id = f1ap_msg->has_old_du_ue_id;
				/* 어느 SRB 로 왔는지를 컨테이너가 말해 주므로 그대로 옮김. 컨테이너가 있기만 하면 SRB1 로
				 *   적으면 안 됨 — 이 메시지는 RRCReject 를 SRB0 으로 명시해 싣는 갈래가 있어(TS 38.473 §9.2.2.5)
				 *   그 경우 이름이 거짓이 됨.
				 *   여러 개면 첫 컨테이너를 따름 — 이 메시지의 RRC 컨테이너 IE 는 하나뿐임(§9.2.2.5). */
			event.payload.f1_release.rrc_container_kind = TR_RRC_CONTAINER_NONE;
			if (f1ap_msg->rrc_container_count > 0)
				event.payload.f1_release.rrc_container_kind =
					(f1ap_msg->rrc_containers[0].srb_id == 0) ? TR_RRC_CONTAINER_SRB0 : TR_RRC_CONTAINER_SRB1;
			emit(obs, &event);
			// COMMAND 로는 레코드를 지우지 않음. COMPLETE 나 유예 만료에서 정리함
			ue_state->releasing = true; ue_state->release_cmd_ns = obs->now_ns;
			return;   // 컨테이너를 이미 처리했으므로 아래 일반 루프를 건너뜀
		} else {   // RELEASE COMPLETE
			struct obs_event event; fill_event_header(&event, obs, sctp_message, TR_EVENT_F1_UE_CTX_RELEASE_COMPLETE, direction); fill_f1ue(&event, ue_state);
			emit(obs, &event);
			ue_remove(obs, idx);   // 이제 빈 칸으로 반납. COMPLETE 에서 소멸시킴
			return;
		}
		break;
	default:
		break;
	}

	// RRC 컨테이너 루프. RELEASE COMMAND 의 rrcRelease 는 위에서 따로 처리함
	for (int item_index = 0; item_index < f1ap_msg->rrc_container_count; item_index++)
		handle_rrc_container(obs, sctp_message, f1ap_msg, ue_state, direction, &f1ap_msg->rrc_containers[item_index]);
}

// ---- N2 단말 레코드와 이벤트 ------------------------------------------------------------
static uint32_t n2_bucket(uint32_t assoc_id, uint64_t ran_ue_ngap_id, uint32_t bucket_count)
{
	uint64_t hash_key = ((uint64_t)assoc_id << 32) ^ ran_ue_ngap_id;
	hash_key = (hash_key ^ (hash_key >> 30)) * 0xbf58476d1ce4e5b9ULL; hash_key ^= hash_key >> 27;
	return (uint32_t)(hash_key % bucket_count);
}
static void n2_lru_unlink(struct obs *obs, int i)
{
	struct obs_n2_state *n2_state = &obs->n2_states[i];
	if (n2_state->lru_prev >= 0) obs->n2_states[n2_state->lru_prev].lru_next = n2_state->lru_next; else obs->n2_lru_head = n2_state->lru_next;
	if (n2_state->lru_next >= 0) obs->n2_states[n2_state->lru_next].lru_prev = n2_state->lru_prev; else obs->n2_lru_tail = n2_state->lru_prev;
	n2_state->lru_prev = n2_state->lru_next = -1;
}
static void n2_lru_push(struct obs *obs, int i)
{
	struct obs_n2_state *n2_state = &obs->n2_states[i];
	n2_state->lru_prev = obs->n2_lru_tail; n2_state->lru_next = -1;
	if (obs->n2_lru_tail >= 0) obs->n2_states[obs->n2_lru_tail].lru_next = i; else obs->n2_lru_head = i;
	obs->n2_lru_tail = i;
}
static void n2_touch(struct obs *obs, int i) { n2_lru_unlink(obs, i); n2_lru_push(obs, i); }

static int n2_find(struct obs *obs, uint32_t assoc_id, uint64_t ran_ue_ngap_id)
{
	for (int i = obs->n2_hash_buckets[n2_bucket(assoc_id, ran_ue_ngap_id, obs->n2_hash_bucket_count)]; i >= 0; i = obs->n2_states[i].hash_next)
		if (obs->n2_states[i].used && obs->n2_states[i].assoc_id == assoc_id && obs->n2_states[i].ran_ue_ngap_id == ran_ue_ngap_id) return i;
	return -1;
}
static void n2_hash_remove(struct obs *obs, int idx)
{
	uint32_t bucket = n2_bucket(obs->n2_states[idx].assoc_id, obs->n2_states[idx].ran_ue_ngap_id, obs->n2_hash_bucket_count);
	int *hash_link = &obs->n2_hash_buckets[bucket];
	while (*hash_link >= 0) { if (*hash_link == idx) { *hash_link = obs->n2_states[idx].hash_next; return; } hash_link = &obs->n2_states[*hash_link].hash_next; }
}
static void n2_remove(struct obs *obs, int idx)   // 표에서만 제거함. 이벤트는 호출자가 냄
{
	n2_hash_remove(obs, idx);
	n2_lru_unlink(obs, idx);
	obs->n2_states[idx].used = false;   // record_id 로 슬롯 재사용을 가리므로 세대 번호는 두지 않음
	obs->n2_states[idx].hash_next = obs->n2_free; obs->n2_free = idx;
	obs->n2_count--;
}
static void fill_n2ue(struct obs_event *event, const struct obs_n2_state *n2_state)
{
	event->n2ue.valid = true;
	event->n2ue.assoc_id = n2_state->assoc_id;
	event->n2ue.ran_ue_ngap_id = n2_state->ran_ue_ngap_id;
	if (n2_state->has_amf_ue_ngap_id) { event->n2ue.has_amf_ue_ngap_id = true; event->n2ue.amf_ue_ngap_id = n2_state->amf_ue_ngap_id; }
	event->cell = n2_state->cell;
}
/* attach_f1_pair: N2 레코드가 기억해 둔 F1 단말을 다시 찾아 이벤트에 붙이고 등급을 교차추론으로 내림.
 *   이유: N2 에서 본 사실을 F1 쪽 표 I 에 귀속시켜야 하는데, N2 레코드는 (키, record_id) 만 들고 있어
 *     재조회가 필요함. 그 F1 레코드가 이미 치워졌으면 아무것도 하지 않음 — 없는 귀속을 지어내지 않음.
 *   부작용: event->f1ue, event->cell, event->quality 를 덮어씀. */
static void attach_f1_pair(struct obs *obs, struct obs_event *event, const struct obs_n2_state *n2_state)
{
	if (!n2_state->has_f1_pair)
		return;
	int f1_index = ue_find_record_id(obs, n2_state->f1_pair_assoc, n2_state->f1_pair_du_ue_id, n2_state->f1_pair_record_id);
	if (f1_index < 0)
		return;
	fill_f1ue(event, &obs->ue_states[f1_index]);
	event->quality = TR_QUALITY_CROSS;   // F1 에서 직접 본 값이 아니라 N2 를 거쳐 귀속한 값임
}
static void n2_evict_one(struct obs *obs)
{
	int i = obs->n2_lru_head; if (i < 0) return;
	struct obs_event event; memset(&event, 0, sizeof event);
	event.kind = TR_EVENT_OBS_UE_EVICTED; event.wallclock_ns = obs->now_ns; event.iface = TR_IFACE_N2; event.assoc_id = obs->n2_states[i].assoc_id;
	fill_n2ue(&event, &obs->n2_states[i]);
	emit(obs, &event);
	obs->stats.ue_evicted_count++;
	n2_remove(obs, i);
}
static int n2_create(struct obs *obs, uint32_t assoc_id, uint64_t ran_ue_ngap_id)
{
	if (obs->n2_count >= obs->obs_cfg.n2_capacity) n2_evict_one(obs);
	if (obs->n2_free < 0) return -1;
	int i = obs->n2_free; obs->n2_free = obs->n2_states[i].hash_next;
	struct obs_n2_state *n2_state = &obs->n2_states[i];
	memset(n2_state, 0, sizeof *n2_state);
	n2_state->record_id = ++obs->next_record_id;   // 생성마다 전역에서 유일한 번호. 슬롯이 재사용돼도 겹치지 않음
	n2_state->nas_ciph_alg = -1;   // 모름. 0 은 5G-EA0 이라는 정당한 값이라 센티널을 둠. SMC 에서 학습함
	n2_state->nas_ciph_alg_before_smc = -1;
	n2_state->used = true; n2_state->assoc_id = assoc_id; n2_state->ran_ue_ngap_id = ran_ue_ngap_id;
	n2_state->created_ns = n2_state->last_ns = obs->now_ns;
	n2_state->lru_prev = n2_state->lru_next = -1;
	uint32_t bucket = n2_bucket(assoc_id, ran_ue_ngap_id, obs->n2_hash_bucket_count);
	n2_state->hash_next = obs->n2_hash_buckets[bucket]; obs->n2_hash_buckets[bucket] = i;
	n2_lru_push(obs, i);
	obs->n2_count++;
	return i;
}

/* amf_id_for: AMF Name 으로 그 AMF 의 키 번호를 돌려줌(없으면 새로 매김). 못 매기면 0.
 *   왜 이름인가: 한 AMF 가 TNL 연결(TNLA)을 여럿 둘 수 있어서(TS 38.413 §8.7), 연결 번호로 AMF 를
 *     대리하면 한 연결로 온 OVERLOAD START 가 같은 AMF 의 다른 연결에 안 걸림.
 *     Served GUAMI List 는 AMF CONFIGURATION UPDATE 로 바뀌므로 신원으로 쓰면 같은 AMF 가 둘로 갈림.
 *     AMF Name 은 NG SETUP RESPONSE 의 필수 IE 임(TS 38.413 §9.2.6.2).
 *   0 을 '모름' 으로 쓰므로 번호는 1부터 매김. 상한을 넘기면 0 을 돌려주고 셈(추측 금지, fail-closed). */
static uint32_t amf_id_for(struct obs *obs, const uint8_t *amf_name, size_t amf_name_len)
{
	if (!amf_name || amf_name_len == 0) return 0;
	uint64_t name_hash, unused_hi;
	nas_hash128(amf_name, amf_name_len, &name_hash, &unused_hi);
	for (uint32_t i = 0; i < obs->amf_key_count; i++)
		if (obs->amf_keys[i].used && obs->amf_keys[i].name_hash == name_hash) return obs->amf_keys[i].amf_id;
	if (obs->amf_key_count == AMF_KEY_MAX) { obs->stats.amf_key_table_full_count++; return 0; }
	uint32_t i = obs->amf_key_count++;
	obs->amf_keys[i].name_hash = name_hash;
	obs->amf_keys[i].amf_id = i + 1;
	obs->amf_keys[i].used = true;
	return obs->amf_keys[i].amf_id;
}

static void fill_event_header_n2(struct obs_event *event, struct obs *obs, const struct sctp_message *sctp_message,
					enum tr_event_kind kind, enum tr_direction direction)
{
	fill_event_header(event, obs, sctp_message, kind, direction);
	event->iface = TR_IFACE_N2;
	/* AMF 키 번호를 그 연결에서 꺼내 모든 N2 이벤트에 실음. 아직 NG SETUP RESPONSE 를 못 봤으면 0(모름)이고,
	 *   집계 쪽은 그때만 연결 번호로 대리함. */
	const struct obs_assoc_record *assoc_record = assoc_get(obs, sctp_message->assoc_id);
	event->amf_id = assoc_record ? assoc_record->amf_id : 0;
}

/* ngap_proc_direction: NGAP 절차 코드와 PDU 종류로 방향을 정함 — F1 쪽 f1ap_proc_direction 과 같은 모양.
 *   근거(1차 출처): asn1/ngap-15.8.0.asn1 의 NGAP-ELEMENTARY-PROCEDURE 구성(어느 메시지가 INITIATING /
 *     SUCCESSFUL / UNSUCCESSFUL 인지)과 절차 코드 값 — 이 열거형의 14개 값 전부를 그 파일과 대조해 확인.
 *   'AMF 가 개시했나' 를 bool 로만 들고 있으면 두 가지가 틀림:
 *     (1) PATH SWITCH(25)가 기본 분기로 떨어져 언제나 상행이 됨 — PathSwitchRequestAcknowledge 와 Failure 는
 *         AMF 에서 CU 로 옴(문법에 SUCCESSFUL 과 UNSUCCESSFUL 이 있음).
 *     (2) 모르는 절차까지 'RAN 개시 = 상행' 으로 추측함. bool 에는 미상을 담을 칸이 없음.
 *   NG RESET(20)은 양쪽이 개시할 수 있어 절차로는 정해지지 않음(TS 38.413 §8.7.4.2.1 과 §8.7.4.2.2).
 *   반환: TR_DIRECTION_DOWN(AMF -> CU) / TR_DIRECTION_UP(CU -> AMF) / TR_DIRECTION_UNKNOWN. */
static enum tr_direction ngap_proc_direction(long proc_code, enum ngap_pdu_type pdu_type)
{
	bool initiating = pdu_type == NGAP_PDU_INITIATING;
	switch (proc_code) {
	// AMF 가 개시하고 INITIATING 만 있는 절차 → AMF→CU(DOWN)
	case NP_DL_NAS: case NP_PAGING: case NP_OVERLOAD_START: case NP_OVERLOAD_STOP: case NP_REROUTE_NAS:
		return initiating ? TR_DIRECTION_DOWN : TR_DIRECTION_UNKNOWN;
	// AMF 가 개시: REQUEST/COMMAND = AMF→CU, RESPONSE/COMPLETE/FAILURE = CU→AMF
	/*   UE CONTEXT MODIFICATION(40)도 AMF 가 개시함(TS 38.413 §8.3.4, 문법의 uEContextModification 에 성공과
	 *   실패 결과가 있음). 이 표에 없으면 와이어 포트 규칙에만 기대게 되고, IANA 포트를 쓰지 않는 망에서는
	 *   미상이 돼 IE 40(New AMF-UE-NGAP-ID) 학습이 빠짐. */
	case NP_INITIAL_CONTEXT_SETUP: case NP_PDU_SESSION_SETUP: case NP_UE_CONTEXT_RELEASE: case NP_UE_CONTEXT_MODIFICATION:
		return initiating ? TR_DIRECTION_DOWN : TR_DIRECTION_UP;
	// RAN(CU)이 개시: REQUEST = CU→AMF, RESPONSE/ACK/FAILURE = AMF→CU
	case NP_NG_SETUP: case NP_PATH_SWITCH:
		return initiating ? TR_DIRECTION_UP : TR_DIRECTION_DOWN;
	/* RAN(CU)이 개시하고 INITIATING 만 있는 절차 → CU→AMF(UP).
	 *   RRC INACTIVE TRANSITION REPORT(37)이 여기 드는 근거: asn1/ngap-15.8.0.asn1 의
	 *   `rRCInactiveTransitionReport NGAP-ELEMENTARY-PROCEDURE ::= { INITIATING MESSAGE … }` 에
	 *   successfulOutcome/unsuccessfulOutcome 이 없고, 상태를 보고하는 쪽이 NG-RAN 노드임. */
	case NP_INITIAL_UE_MESSAGE: case NP_UPLINK_NAS: case NP_NAS_NON_DELIVERY: case NP_RRC_INACTIVE_TRANSITION:
		return initiating ? TR_DIRECTION_UP : TR_DIRECTION_UNKNOWN;
	default:
		return TR_DIRECTION_UNKNOWN;   /* NG RESET(양방향), 그 밖의 미확인 절차: 추측 금지 → 와이어 규칙 */
	}
}

// corr_on_n2: INITIAL UE MESSAGE 가 도착하면 대기 중인 F1 항목과 매칭함. 성사되면 N2 레코드에 상대 키를 적음.
static void corr_on_n2(struct obs *obs, const struct tr_nr_cgi *cell, int est_cause, const uint8_t *nas_bytes, uint32_t nas_ie_len,
					   uint64_t wallclock_ns, uint32_t assoc_id, uint64_t ran_ue_ngap_id)
{
	if (!nas_bytes || nas_ie_len == 0 || est_cause < 0 || !cell || !cell->valid) return;
	uint32_t plmn_packed = plmn_pack(cell->plmn_bytes);
	uint64_t hash_lo, hash_hi; nas_hash128(nas_bytes, nas_ie_len, &hash_lo, &hash_hi);
	struct corr_key *corr_key = corr_key_get(obs, plmn_packed, cell->cell_id, est_cause, nas_ie_len, hash_lo, hash_hi, false);
	if (!corr_key) corr_key = corr_key_get(obs, plmn_packed, cell->cell_id, CORR_EST_CAUSE_ANY, nas_ie_len, hash_lo, hash_hi, false);   // 정확한 키가 없으면 폴백 세션이 쓰는 원인 없는 키로 한 번 더 찾음
	if (!corr_key) { obs->stats.corr_unmatched_n2_count++; return; }
	if (corr_key->ambiguous_until_ns >= wallclock_ns) { obs->stats.corr_ambiguous_count++; corr_key->ambiguous_until_ns = wallclock_ns + obs->correlation_window_ns; return; }
	corr_key_expire_items(obs, corr_key, wallclock_ns);
	int pending_count = corr_key->pending_count;
	if (pending_count == 0) { obs->stats.corr_unmatched_n2_count++; corr_key_free_if_empty(obs, corr_key, wallclock_ns); return; }
	if (pending_count == 1) {
		struct corr_item *corr_item = &obs->corr_items[corr_key->item_head];
		if (corr_item->wallclock_ns > wallclock_ns) { obs->stats.corr_unmatched_n2_count++; return; }   // F1 항목이 N2 보다 늦게 찍힌 짝은 버림. 시간 순서가 거꾸로임
		uint32_t f1_assoc = corr_item->assoc_id, f1_du_ue_id = corr_item->du_ue_id; uint64_t f1_record_id = corr_item->f1_record_id;
		int head = corr_key->item_head; corr_key->item_head = corr_item->next_index; corr_key->pending_count--; corr_item_free_one(obs, head);   /* 대기열에서 빼기 */
		int f1_index = ue_find_record_id(obs, f1_assoc, f1_du_ue_id, f1_record_id);   // record_id 로 슬롯 재사용을 걸러 남의 단말에 귀속되는 것을 막음
		int n2_index = n2_find(obs, assoc_id, ran_ue_ngap_id);
		if (f1_index >= 0 && n2_index >= 0) {   // 양쪽 다 있을 때만 키를 적음
			/* 매칭 결과를 N2 레코드에만 적음. 읽는 쪽이 N2 에서 F1 한 방향뿐이라 반대 방향은 둘 이유가 없음.
			 *   record_id 를 같이 적는 이유: 나중에 그 F1 슬롯이 다른 단말에게 재사용됐는지 가리기 위해서임. */
			struct obs_n2_state *n2_state = &obs->n2_states[n2_index];
			n2_state->has_f1_pair      = true;
			n2_state->f1_pair_assoc     = f1_assoc;
			n2_state->f1_pair_du_ue_id  = f1_du_ue_id;
			n2_state->f1_pair_record_id = obs->ue_states[f1_index].record_id;
			obs->stats.corr_unique_count++;
		} else {
			obs->stats.corr_unmatched_n2_count++;   // F1 단말이 재사용된 슬롯이거나 N2 를 못 찾음. 매칭하지 않아 오귀속을 막음
		}
		corr_key_free_if_empty(obs, corr_key, wallclock_ns);
		return;
	}
	/* 대기 항목이 둘 이상이면 모호함. 전부 빼고 표지만 남김 — 어떤 것을 골라도 셀과 원인 칸이 같아서
	 * 고를 근거가 없음. 지어내는 대신 모호로 카운팅함. */
	obs->stats.corr_ambiguous_count += (uint64_t)pending_count + 1;
	while (corr_key->item_head >= 0) { int next_index = obs->corr_items[corr_key->item_head].next_index; corr_item_free_one(obs, corr_key->item_head); corr_key->item_head = next_index; }
	corr_key->pending_count = 0; corr_key->ambiguous_until_ns = wallclock_ns + obs->correlation_window_ns;
}

// n2_find_by_amf_ue_ngap_id: 같은 연결에서 AMF-UE-NGAP-ID 로 N2 레코드를 찾음. 없으면 -1. 해제, 리셋 경로뿐이라 선형 탐색.
static int n2_find_by_amf_ue_ngap_id(const struct obs *obs, uint32_t assoc_id, uint64_t amf_ue_ngap_id)
{
	for (uint32_t i = 0; i < obs->n2_capacity; i++)
		if (obs->n2_states[i].used && obs->n2_states[i].assoc_id == assoc_id && obs->n2_states[i].has_amf_ue_ngap_id && obs->n2_states[i].amf_ue_ngap_id == amf_ue_ngap_id)
			return (int)i;
	return -1;
}

// n2_reset_all: NG RESET(reset-all)로 그 연결의 N2 레코드를 전부 지움.
static void n2_reset_all(struct obs *obs, uint32_t assoc_id)
{
	for (uint32_t i = 0; i < obs->n2_capacity; i++)
		if (obs->n2_states[i].used && obs->n2_states[i].assoc_id == assoc_id) { n2_remove(obs, (int)i); obs->stats.ng_reset_removed_count++; }
}

/* n2_reset_part: NG RESET(partOfNG-Interface)로 목록의 UE 만 지움. 항목은 RAN ID 또는 AMF ID 한쪽만, 또는 둘 다 없을 수 있음
 *   (TS 38.413 §9.3.3.25 둘 다 OPTIONAL). 둘 다 없는 항목은 지울 대상이 없어 지나감. */
static void n2_reset_part(struct obs *obs, uint32_t assoc_id, const struct ngap_msg *ngap_msg)
{
	for (int reset_index = 0; reset_index < ngap_msg->reset_ue_count; reset_index++) {
		const struct ngap_reset_ue *reset_ue = &ngap_msg->reset_ues[reset_index];
		int found = reset_ue->has_ran_ue_ngap_id ? n2_find(obs, assoc_id, reset_ue->ran_ue_ngap_id) : -1;
		if (found < 0 && reset_ue->has_amf_ue_ngap_id) found = n2_find_by_amf_ue_ngap_id(obs, assoc_id, reset_ue->amf_ue_ngap_id);
		if (found >= 0) { n2_remove(obs, found); obs->stats.ng_reset_removed_count++; }
	}
}

// ---- NGAP 메시지 하나 처리 --------------------------------------------------------------
/* handle_ngap: NGAP 메시지 하나를 이벤트로 바꿈. handle_f1ap 과 같은 모양 — 연결 수준 절차는 거기서
 *   끝나고, 단말 수준 절차만 아래로 내려가 N2 레코드를 만지고 NAS-PDU 를 품.
 *
 *     방향 판정 --> IE 계수기 누적 --> 연결 수준 절차 --여기서 끝남--> return
 *                                  --> 단말 수준 절차 --> 레코드 찾기, 생성 --> NAS 운반 루프
 *
 *     연결 수준   NG RESET               범위가 전체면 그 연결의 N2 표를 비우고, 일부면 목록의 단말만
 *                 NG SETUP               RESPONSE 의 AMF Name 으로 그 AMF 의 키 번호를 매김
 *                 OVERLOAD START, STOP   AMF 과부하. 레코드는 건드리지 않음
 *                 PAGING                 레코드가 변하지 않아 바로 돌아감
 *     단말 수준   INITIAL UE MESSAGE     N2 레코드 생성. 대기 중인 F1 항목과 매칭
 *                 DL NAS, UL NAS 등      NAS-PDU 하나마다 이벤트. 알고리즘 학습과 보안 헤더 방향 판정
 *                 UE CONTEXT RELEASE     COMMAND 는 유예 표시만 하고, COMPLETE 에서 레코드를 지움
 *                 RRC INACTIVE TRANSITION REPORT   RRC 상태를 올림
 *
 *   부작용: 이벤트 방출, obs->stats 갱신, N2 표와 연결 레코드 변경. */
static void handle_ngap(struct obs *obs, const struct sctp_message *sctp_message, const struct ngap_msg *ngap_msg)
{
	long proc_code = ngap_msg->procedure_code;
	// 방향은 절차와 PDU 종류로 먼저, 다음에 와이어 포트 규칙, 그래도 모르면 미상. handle_f1ap 과 같은 순서
	enum tr_direction direction = decide_direction(obs, sctp_message->record, TR_IFACE_N2,
									   ngap_proc_direction(proc_code, ngap_msg->pdu_type));

	/* 문법 15.8.0 에 없는 (절차, PDU 종류) 짝은 여기 오지 않음 — ngap_parse 가 NGAP_UNKNOWN_MESSAGE 를
	 *   돌려주고 obs_on_sctp 가 ap_body_unknown_count 로 카운팅함. 그래서 `20 16 40 02 de ad`(successfulOutcome,
	 *   절차 22, 쓰레기) 같은 입력이 OVERLOAD START 이벤트가 되지 않음. */

	/* ngap.c 가 '있었지만 담지 않은' IE 를 센 값. 여기서 누적하지 않으면 libap 밖으로 나가지 않아,
	 * 버렸다는 사실이 아무 데도 남지 않음. */
	obs->stats.ngap_unknown_ie_count += (uint64_t)ngap_msg->unknown_ie_count;
	obs->stats.ngap_rejected_ie_count += (uint64_t)ngap_msg->rejected_ie_count;
	obs->stats.ngap_duplicate_ie_count += (uint64_t)ngap_msg->duplicate_ie_count;
	obs->stats.ngap_type_mismatch_ie_count += (uint64_t)ngap_msg->type_mismatch_ie_count;

	/* NG RESET(reset-all, initiatingMessage): 그 연결의 N2 레코드를 전부 지움(TS 38.413 §8.7.4.2.1 AMF 개시, §8.7.4.2.2 NG-RAN 개시 — 받은 쪽이 가리킨 UE 연결을 전부 해제).
	 * 지우지 않으면 리셋 뒤 재사용된 RAN-UE-NGAP-ID 가 '옛 종료 놓침(교체)' 으로 세어짐. 부분 리셋(UE 목록)은 목록의 UE 만 지움. */
	if (proc_code == NP_NG_RESET) {
		if (ngap_msg->pdu_type != NGAP_PDU_INITIATING) return;   // ACKNOWLEDGE 에는 ResetType 이 없음
		if (ngap_msg->reset_type == RESET_TYPE_ALL) n2_reset_all(obs, sctp_message->assoc_id);
		if (ngap_msg->reset_type == RESET_TYPE_PART) n2_reset_part(obs, sctp_message->assoc_id, ngap_msg);
		return;
	}

	// --- 비-UE-associated: AMF 레벨 ---
	if (proc_code == NP_NG_SETUP) {
		/* AMF Name 과 Served GUAMI 는 RESPONSE 에만 있음. UE Retention(IE 147)은 REQUEST 에도 실릴 수 있지만,
		 * REQUEST 에는 AMF 를 가릴 값이 없어 이벤트를 내지 않음. */
		if (ngap_msg->pdu_type != NGAP_PDU_INITIATING) {
			// AMF 키 학습은 이벤트 헤더를 채우기 전에 — 이 NG SETUP 자신도 그 번호를 달고 나가야 함
			if (ngap_msg->pdu_type == NGAP_PDU_SUCCESSFUL) {
				struct obs_assoc_record *assoc_record = assoc_get(obs, sctp_message->assoc_id);
				if (assoc_record)
					assoc_record->amf_id = amf_id_for(obs, (const uint8_t *)ngap_msg->amf_name, ngap_msg->amf_name_len);
			}
			struct obs_event event; fill_event_header_n2(&event, obs, sctp_message, TR_EVENT_NG_SETUP, direction);
			if (ngap_msg->amf_name) { event.payload.ng_setup.amf_name.bytes = (const uint8_t *)ngap_msg->amf_name; event.payload.ng_setup.amf_name.len = ngap_msg->amf_name_len; }
			event.payload.ng_setup.guami_digest = ngap_msg->guami_digest;
			event.payload.ng_setup.ue_contexts_retained = ngap_msg->ue_contexts_retained;
			event.payload.ng_setup.outcome_failure = (ngap_msg->pdu_type == NGAP_PDU_UNSUCCESSFUL);
			emit(obs, &event);
		}
		return;
	}
	if (proc_code == NP_OVERLOAD_START || proc_code == NP_OVERLOAD_STOP) {
		struct obs_event event;
		fill_event_header_n2(&event, obs, sctp_message, proc_code == NP_OVERLOAD_START ? TR_EVENT_NG_OVERLOAD_START : TR_EVENT_NG_OVERLOAD_STOP, direction);
		if (proc_code == NP_OVERLOAD_START) {
			event.payload.overload.has_action = ngap_msg->overload_response_present;
			event.payload.overload.action_mask = ngap_msg->overload_action_mask;
			event.payload.overload.traffic_load_reduction_pct = ngap_msg->traffic_load_reduction_percent;
			event.payload.overload.nssai_list_present = ngap_msg->overload_nssai_list_present;
		}
		emit(obs, &event);
		return;
	}
	if (proc_code == NP_PAGING) return;   // 단말에 묶이지 않는 절차이고 레코드도 변하지 않음

	// --- UE-associated: RAN-UE-NGAP-ID 필요 ---
	uint32_t assoc_id = sctp_message->assoc_id; uint64_t ran_ue_ngap_id = ngap_msg->ran_ue_ngap_id; bool has_ran_ue_ngap_id = ngap_msg->has_ran_ue_ngap_id;
	/* UE CONTEXT RELEASE COMMAND 의 UE-NGAP-IDs 는 (AMF ID, RAN ID) 짝이거나 AMF ID 단독임(TS 38.413 §9.2.2.5).
	 * 단독 형태를 통째로 버리면 그 단말의 해제 이벤트와 등록 해제 원인이 사라짐. 같은 연결에서 AMF ID 로
	 * 레코드를 찾아 RAN ID 를 되찾음(해제 경로뿐이라 선형 탐색으로 충분). */
	if (!has_ran_ue_ngap_id && proc_code == NP_UE_CONTEXT_RELEASE && ngap_msg->pdu_type == NGAP_PDU_INITIATING && ngap_msg->has_amf_ue_ngap_id) {
		int by_amf_index = n2_find_by_amf_ue_ngap_id(obs, assoc_id, ngap_msg->amf_ue_ngap_id);
		if (by_amf_index >= 0) { ran_ue_ngap_id = obs->n2_states[by_amf_index].ran_ue_ngap_id; has_ran_ue_ngap_id = true; }
	}
	if (!has_ran_ue_ngap_id) return;
	int idx = n2_find(obs, assoc_id, ran_ue_ngap_id);

	// 레코드 생성은 INITIAL UE MESSAGE 에서만. 살아 있는 키가 다시 오면 재사용이므로 옛 레코드를 닫고 새로 만듦
	if (proc_code == NP_INITIAL_UE_MESSAGE) {
		/* 이 블록이 아래 nas_pdu_mandatory 검사보다 먼저 돌아가므로, NAS-PDU 가 필수인 네 절차 중 INITIAL UE
		 * MESSAGE 만 거기서 세어지지 않음. 그래서 여기서 따로 셈 — 넷 중 셋만 세고 있던 비대칭을 없앰.
		 * 와이어 사실이라 레코드를 만들기 전에 셈(아래 idx<0 return 보다 앞). TS 38.413 §9.2.5.1 에서 M 임. */
		if (ngap_msg->nas_ie_count == 0) obs->stats.nas_pdu_absent_count++;
		if (idx >= 0) { n2_remove(obs, idx); obs->stats.ue_replaced_count++; }   // 옛 종료를 놓친 것이므로 닫음. 옛 record_id 는 이제 유효하지 않음
		idx = n2_create(obs, assoc_id, ran_ue_ngap_id);
		if (idx < 0) return;
		if (ngap_msg->uli_nr_cgi.is_valid) obs->n2_states[idx].cell = tr_nr_cgi_from(&ngap_msg->uli_nr_cgi);
		struct obs_event event; fill_event_header_n2(&event, obs, sctp_message, TR_EVENT_NG_INITIAL_UE_MESSAGE, direction); fill_n2ue(&event, &obs->n2_states[idx]);
		event.payload.initial_ue.est_cause = ngap_msg->rrc_establishment_cause;
		if (ngap_msg->nas_ie_count > 0) {
			/* 여기서 디코드하는 이유는 값이 아니라 계수기임. 이 위치의 NAS 는 RRCSetupComplete 과 같은 바이트이고
			 * (CU 는 해석 없이 넘김 — TS 38.413 §9.3.3.4 "transferred without interpretation in the NG-RAN node"),
			 * 표 I 는 F1 단말로 키를 매기는데 이 이벤트에는 매칭된 F1 단말이 아직 없음(매칭은 아래 corr_on_n2 가 함).
			 * 그래서 꺼낸 값을 실을 칸이 없음. 그래도 N2 만 탭하는 배치에서는 이 위치가 NAS 가시성의 유일한
			 * 출처이므로, 해석하지 못한 것과 방향이 어긋난 것은 카운팅함. */
			struct nas_msg nas_msg;
			int parse_result = nas_parse(ngap_msg->nas_ies[0].data, ngap_msg->nas_ies[0].len, obs->n2_states[idx].nas_ciph_alg, &nas_msg);
			// INITIAL UE MESSAGE 는 UE→AMF 뿐임(TS 38.413 §8.6.1)
			nas_accept_result(obs, &nas_msg, TR_DIRECTION_UP);
			/* SMC 는 AMF→UE 라서(표 8.2.25.1.1) 여기 SMC 모양의 NAS 가 있다면 단말이 만든 것임 —
			 * 학습하면 그 단말이 자기 암호문을 평문으로 읽히게 만들 수 있으므로 학습하지 않고 셈. */
			if (parse_result != 0)          obs->stats.nas_malformed_count++;
			else if (nas_msg.has_sec_alg)   obs->stats.nas_smc_learn_skipped_count++;
		}
		emit(obs, &event);
		// INITIAL UE MESSAGE 의 NAS 와 셀과 원인으로 대기 중인 F1 항목(RRCSetupComplete)과 매칭
		if (ngap_msg->nas_ie_count > 0) {
			struct tr_nr_cgi uli_cell = tr_nr_cgi_from(&ngap_msg->uli_nr_cgi);
			corr_on_n2(obs, &uli_cell, ngap_msg->rrc_establishment_cause, ngap_msg->nas_ies[0].data, (uint32_t)ngap_msg->nas_ies[0].len,
					   event.wallclock_ns, assoc_id, ran_ue_ngap_id);
		}
		return;   // CU 에서 AMF 로 가는 메시지라 아래 NAS 운반과 해제 처리에 해당 없음
	}
	// 수립을 못 본 단말의 해제로는 레코드를 만들지 않음. 만들면 없던 단말이 생겨 수립 없는 종료가 흘러감
	if (idx < 0 && proc_code == NP_UE_CONTEXT_RELEASE) return;
	if (idx < 0) {   // INITIAL UE MESSAGE 를 못 보고 등장(late join). AMF 쪽 번호는 미상
		idx = n2_create(obs, assoc_id, ran_ue_ngap_id);
		if (idx < 0) return;
	}
	struct obs_n2_state *n2_state = &obs->n2_states[idx];
	n2_state->last_ns = obs->now_ns; n2_touch(obs, idx);
	if (ngap_msg->uli_nr_cgi.is_valid) n2_state->cell = tr_nr_cgi_from(&ngap_msg->uli_nr_cgi);

	/* AMF 쪽 단말 번호 학습. AMF 에서 CU 로 온 메시지가 amf_ue_ngap_id 를 실었고 레코드가 아직 모를 때임.
	 * REROUTE NAS REQUEST 는 연결을 세우는 것이 아니라 다른 AMF 로 돌리는 것이라 성공 신호에서 뺌. */
	if (direction == TR_DIRECTION_DOWN && ngap_msg->has_amf_ue_ngap_id && proc_code != NP_REROUTE_NAS) {
		if (!n2_state->has_amf_ue_ngap_id) { n2_state->has_amf_ue_ngap_id = true; n2_state->amf_ue_ngap_id = ngap_msg->amf_ue_ngap_id; }   // 신원 학습은 모든 하행에서 함
		/* 단말 연결 수립의 성공으로 세는 것은 CU 가 AMF 쪽 번호를 그 단말에 연관시키는 두 메시지뿐임 —
		 * DOWNLINK NAS TRANSPORT 와 INITIAL CONTEXT SETUP REQUEST. 해제 명령이나 PDU 세션 같은 다른 하행은
		 * 이미 있는 번호를 참조하는 것이라 성공이 아님. 그래서 신원 학습과 분리해 한 번만 발화함. */
		bool first_for_ran_ue_ngap_id = !n2_state->uecntx_succ_sent && (proc_code == NP_DL_NAS || proc_code == NP_INITIAL_CONTEXT_SETUP);
		if (first_for_ran_ue_ngap_id) n2_state->uecntx_succ_sent = true;
		struct obs_event event; fill_event_header_n2(&event, obs, sctp_message, TR_EVENT_NG_AMF_DL_UE_MSG, direction); fill_n2ue(&event, n2_state);
		event.payload.amf_dl.proc_code = (int)proc_code;
		event.payload.amf_dl.has_amf_ue_ngap_id = true;
		event.payload.amf_dl.first_for_ran_ue_ngap_id = first_for_ran_ue_ngap_id;
		emit(obs, &event);
	} else if (ngap_msg->has_amf_ue_ngap_id && !n2_state->has_amf_ue_ngap_id) {
		n2_state->has_amf_ue_ngap_id = true; n2_state->amf_ue_ngap_id = ngap_msg->amf_ue_ngap_id;   // 상행에서 먼저 보이면 학습만 하고 성공으로 세지 않음
	}

	/* New AMF-UE-NGAP-ID(IE 40, UE CONTEXT MODIFICATION REQUEST, AMF→CU): 이 UE 의 AMF 쪽 ID 가 바뀜(TS 38.413 §8.3.4.2).
	 *   안 배우면 이후 AMF ID 만 오는 UE CONTEXT RELEASE COMMAND 의 역조회가 옛 ID 로 실패함. */
	if (direction == TR_DIRECTION_DOWN && ngap_msg->has_new_amf_ue_ngap_id) { n2_state->has_amf_ue_ngap_id = true; n2_state->amf_ue_ngap_id = ngap_msg->new_amf_ue_ngap_id; }

	/* NAS-PDU 가 필수인 네 절차(TS 38.413 §9.2.5.1, §9.2.5.3, §9.2.5.4, §9.2.5.5 에서 IE 38 이 M).
	 *   IE 컨테이너가 SEQUENCE OF 라 asn1c 가 mandatory 를 강제하지 못하므로, 없는 입력이 들어옴. */
	// INITIAL UE MESSAGE(15)는 위 전용 블록에서 세고 여기 도달하지 못하므로 이 목록에 두지 않음.
	bool nas_pdu_mandatory = (proc_code == NP_DL_NAS || proc_code == NP_UPLINK_NAS
						   || proc_code == NP_NAS_NON_DELIVERY);
	if (nas_pdu_mandatory && ngap_msg->nas_ie_count == 0) obs->stats.nas_pdu_absent_count++;

	// NAS-PDU(IE 38) 하나마다 이벤트 하나. 보안 헤더 형은 암호와 무관하게 보임
	for (int nas_index = 0; nas_index < ngap_msg->nas_ie_count; nas_index++) {
		struct obs_event event; fill_event_header_n2(&event, obs, sctp_message, TR_EVENT_NG_NAS, direction); fill_n2ue(&event, n2_state);
		/* NASNonDeliveryIndication(19) 의 NAS 는 UE 에 '전달 실패'한 DL NAS →
		 * non_delivered 표식(tr on_nas 가 이것으로 5GMM 상태 전진을 막음). 그 외 proc_code=전달됨(false). */
		nas_values_init(&event.payload.nas);
		event.payload.nas.non_delivered = (proc_code == NP_NAS_NON_DELIVERY);
		/* NGAP 메시지의 방향과 그 안에 실린 NAS-PDU 의 방향은 다른 개념임.
		 * NASNonDeliveryIndication(19) 은 NG-RAN -> AMF 로 올라오지만(TS 38.413 9.2.5.4 "Direction:
		 * NG-RAN node -> AMF") 그 안의 NAS 는 "reporting the non-delivery of a NAS PDU previously
		 * received within a DOWNLINK NAS TRANSPORT message" 라 하행임. 아래 다섯 판정은 전부 NAS 계층
		 * 사실이므로 NGAP 방향이 아니라 이 방향으로 해야 함. 안 가르면 전달 실패한 정상 하행 NAS 가
		 * (1) 타입을 빼앗기고 방향 위반으로 세어지고 (2) SHT 짝이 어긋남으로 올라가고
		 * (3) 하행 SHT 4 가 'UE 가 보낸 SECURITY MODE COMPLETE' 로 지어내짐 = 확신 있는 오값. */
		enum tr_direction nas_pdu_direction = event.payload.nas.non_delivered ? TR_DIRECTION_DOWN : direction;
		/* 매칭된 F1 레코드가 있으면 그 신원을 실어, 집계 층이 N2 에서 본 NAS 를 F1 쪽 표 I 에 귀속시킴.
		 * (키, record_id) 로 재조회해 슬롯이 재사용된 경우를 걸러 오귀속을 막음. AS 암호가 걸려 F1 쪽 RRC 가
		 * 안 보이는 구간에서도 N2 의 NAS 는 보이므로, 이 귀속이 그 구간의 유일한 NAS 출처임. */
		attach_f1_pair(obs, &event, n2_state);
		/* 그 단말에서 학습한 NAS 암호 알고리즘으로 가시성을 판정함(fail-closed). SMC 가 고른 알고리즘은
		 * 학습해 이후 보호 NAS 의 가독 판정에 씀 — 5G-EA0(0)일 때만 안쪽을 읽음. */
		struct nas_msg nas_msg;
		int parse_result = nas_parse(ngap_msg->nas_ies[nas_index].data, ngap_msg->nas_ies[nas_index].len, n2_state->nas_ciph_alg, &nas_msg);
		event.payload.nas.parse_ok = (parse_result == 0);   // 형식이 정상인지. 잘리거나 깨진 PDU 를 '암호라 못 읽음' 과 구분함
		bool msg_type_usable = nas_accept_result(obs, &nas_msg, nas_pdu_direction);
		/* 실패 경로에서도 sht, epd 를 그대로 씀: libnas 가 "음수 반환 시에도 epd, sht 는 읽은 만큼 유효하고
		 * 없으면 -1" 을 계약으로 적어 두었음. 바이트를 다시 뜯으면 예약 SHT(5~15) 판정이 두 계층에서 갈림. */
		event.payload.nas.sht = nas_msg.sht;                 event.payload.nas.epd = nas_msg.epd;
		/* 보안 헤더 형과 방향의 짝은 규격이 메시지로 못박았음(obs.h 의 표). 어긋난 짝은 조작으로만
		 * 생기고 방향을 아는 계층이 여기뿐이므로, 가독 여부와 무관하게 여기서 한 번 셈.
		 * 하류(tr)는 이 짝으로 NAS 보안상태를 전진시키지 않음.
		 *   parse_result 관문 밖에 두는 이유: libnas 가 "음수 반환 시에도 sht 는 읽은 만큼 유효" 를 계약했고
		 *   (nas.h) 위에서 이미 그 계약으로 sht 를 이벤트에 실었음. 관문 안에 두면 PDU 를 자르는 것만으로
		 *   조작 증거가 사라짐 — 형제 비대칭. 못 읽은 sht 는 -1 이라 걸리지 않음. */
		if (nas_msg.sht == 3 || nas_msg.sht == 4) {
			bool spec_direction_down = (nas_msg.sht == 3);
			if (nas_pdu_direction != TR_DIRECTION_DOWN && nas_pdu_direction != TR_DIRECTION_UP) {
				obs->stats.nas_sec_header_direction_unjudged_count++;
				event.payload.nas.sec_header_direction_ok = false;
			} else if ((nas_pdu_direction == TR_DIRECTION_DOWN) != spec_direction_down) {
				obs->stats.nas_sec_header_direction_mismatch_count++;
				event.payload.nas.sec_header_direction_ok = false;
			}
		}
		if (parse_result == 0) {
			/* NAS SMC 에서 학습. 조건: AMF→UE 방향이고 SHT 3(새 컨텍스트로 무결성 보호). SMC 는 그 방향, 그 SHT 로만 옴
			 * (TS 24.501 Table 8.2.25.1.1, Table 9.3.1 NOTE 1). UL 이나 다른 SHT 의 SMC 모양은 단말이 만든 것이라
			 * 학습하지 않고 셈 — 규격상 없는 조합이므로 조작의 증거임(아래 SHT 4 건과 짝). */
			if (nas_msg.has_sec_alg) {
				/* 전달 실패한 SMC 는 단말이 받지 못했으므로 그 알고리즘을 적용하지 않음. 학습하면 이후
				 * 보호 NAS 의 가시성을 단말이 쓰지 않는 알고리즘으로 판정하게 됨 = 확신 있는 오값. */
				if (nas_pdu_direction == TR_DIRECTION_DOWN && nas_msg.sht == 3
					&& !event.payload.nas.non_delivered) {
					n2_state->nas_ciph_alg_before_smc = n2_state->nas_ciph_alg;
					n2_state->nas_ciph_alg = nas_msg.nas_ciph_alg;
				} else {
					obs->stats.nas_smc_learn_skipped_count++;
				}
			}
			/* 거절되면 SMC 로 배운 알고리즘을 버리고 직전 맥락으로 되돌림(TS 24.501 §5.4.2.5). 안 되돌리면
			 * 이후 보호 NAS 의 가시성 판정이 쓰이지 않는 알고리즘을 기준으로 돌아감 - 평문이 아닌
			 * 것을 평문으로 읽거나(확신 있는 오값) 읽을 수 있는 것을 못 읽음. REJECT 는 옛 맥락으로
			 * 보내므로 옛 알고리즘이 5G-EA0 이면 여기서 읽힘. */
			if (nas_msg.msg_type == NAS_MM_SECURITY_MODE_REJECT && nas_pdu_direction == TR_DIRECTION_UP) {
				n2_state->nas_ciph_alg = n2_state->nas_ciph_alg_before_smc;
				n2_state->nas_ciph_alg_before_smc = -1;
			}
			nas_values_take(&event.payload.nas, &nas_msg, msg_type_usable);
				/* 안쪽을 못 읽은 SHT 4 는 SECURITY MODE COMPLETE 로 추론함. 조건은 상행임 —
				 * 표 9.3.1 NOTE 2 가 SHT 4 를 그 메시지에만 묶고, 그 메시지는 UE 에서 AMF 로만 감(§8.2.26).
				 * 위 SMC 학습(하행, SHT 3)과 짝이 되는 반대 판정이라 같은 곳에 둠 — 방향을 아는 계층이 여기뿐임.
				 * 추론을 안 한 경우는 위 방향 판정이 이미 카운팅했음. */
			if (nas_msg.sht == 4 && !nas_msg.inner_readable && nas_pdu_direction == TR_DIRECTION_UP) {
				event.payload.nas.msg_type = NAS_MM_SECURITY_MODE_COMPLETE;
				event.payload.nas.msg_type_inferred = true;
			}
		} else {
			/* 값 칸은 손대지 않음 — nas_values_init 이 이미 '안 읽음' 으로 두었고, 해석에 실패한 길에서는
			 * nas_values_take 가 돌지 않으므로 그대로 남음. 센티널을 두 번 적으면 한쪽만 늘어남. */
			obs->stats.nas_malformed_count++;   // 이벤트의 parse_ok=false 와 같은 사실의 합계. 전체 몇 건인지는 여기서만 보임
		}
		emit(obs, &event);
	}

	// UE CONTEXT RELEASE. COMMAND 는 AMF 에서 CU 로, COMPLETE 는 CU 에서 AMF 로 옴
	if (proc_code == NP_UE_CONTEXT_RELEASE) {
		if (ngap_msg->pdu_type == NGAP_PDU_INITIATING) {
			struct obs_event event; fill_event_header_n2(&event, obs, sctp_message, TR_EVENT_NG_UE_CTX_RELEASE_CMD, direction); fill_n2ue(&event, n2_state);
			event.payload.ng_cause.cause_group = ngap_msg->cause.group; event.payload.ng_cause.cause_value = ngap_msg->cause.value;
			// 해제 원인이 F1 쪽 표 I 의 5GMM 상태를 바꾸므로(등록 해제 원인이면 DEREGISTERED) 매칭된 F1 에 귀속시킴
			attach_f1_pair(obs, &event, n2_state);
			emit(obs, &event);
			n2_state->releasing = true; n2_state->release_cmd_ns = obs->now_ns;   // 유예 대기. COMPLETE 나 유예 만료에서 정리함
		} else {
			struct obs_event event; fill_event_header_n2(&event, obs, sctp_message, TR_EVENT_NG_UE_CTX_RELEASE_COMPLETE, direction); fill_n2ue(&event, n2_state);
			emit(obs, &event);
			n2_remove(obs, idx);   // COMPLETE 에서 레코드를 지움
		}
	}

	/* RRC INACTIVE TRANSITION REPORT 를 이벤트로 냄.
	 *   왜 내는가: 이 보고에 RRCState=inactive 가 오면 그 단말에 suspendConfig 가 있었다고 바로 확정할 수
	 *     있음. 암호 때문에 RRCRelease 를 못 읽은 구간에서는 이것이 suspend 를 가리는 유일한 증거임.
	 *   매칭된 F1 에 귀속시키는 이유: suspend 판정에 쓰는 값이라 위 해제 경로와 같은 방식으로 붙임.
	 *   fail-closed: IE 92 가 없으면(rrc_state<0) 상태를 지어내지 않고 이벤트를 내지 않음. 대신 그 수를 세어
	 *     "보고는 왔는데 상태를 못 읽었음" 을 신호로 남김. */
	if (proc_code == NP_RRC_INACTIVE_TRANSITION && ngap_msg->pdu_type == NGAP_PDU_INITIATING) {
		if (ngap_msg->rrc_state < 0) {
			obs->stats.rrc_state_report_no_ie_count++;
		} else {
			struct obs_event event; fill_event_header_n2(&event, obs, sctp_message, TR_EVENT_NG_RRC_STATE_REPORT, direction); fill_n2ue(&event, n2_state);
			event.payload.rrc_state_report.rrc_state = ngap_msg->rrc_state;
			attach_f1_pair(obs, &event, n2_state);
			emit(obs, &event);
		}
	}
}

