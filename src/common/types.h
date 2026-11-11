/**
 * common/types.h
 * : 모듈들이 공유하는 기본 타입 - 관측 이벤트 하나
 *
 * [1] 쓰는 쪽도 하나, 읽는 쪽도 하나임.
 *
 *     libobs --struct obs_event--> libtelemetry --common/report.h 구조체--> libsink
 *
 *     libtelemetry 가 셀 카운터로 집계하는 동시에 탐지 줄 세 가지(주기 줄, 단말 줄, DU 줄)로
 *     바꿔 내보냄. 와이어로 나가는 경로가 그 하나임.
 *     읽는 쪽이 하나라서, 여기 칸을 늘리면 libtelemetry 가 읽지 않는 한 아무에게도 닿지 않음.
 *     칸을 넣거나 지우기 전에 그 칸을 읽는 쪽이 있는지 먼저 확인할 것.
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
 *   없으면 그런 경우에도 UP/DOWN 중 하나를 추측해 사실처럼 싣게 됨(= 조용한 오값).
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
	 *   키마다 한 번 배우면 그 단말의 모든 이벤트에 같이 실림 - 모든 줄에서 그 단말을 C-RNTI 로 가릴 수 있게 하고,
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
 *   번호는 ap.h 의 F1AP_PDU_* 와 같은 순서지만 별개 타입임 */
enum tr_ap_outcome {
	TR_AP_OUTCOME_REQUEST = 1,   /* initiatingMessage */
	TR_AP_OUTCOME_SUCCESS,       /* successfulOutcome */
	TR_AP_OUTCOME_FAILURE        /* unsuccessfulOutcome */
};

/* Overload Action 값. payload.overload.action_mask 의 비트 위치이고, 값 순서는 고정 문법
 *   asn1/ngap-15.8.0.asn1:4399 OverloadAction 과 같음. 이름은 그 문법의 값 이름을 옮긴 것임 */
enum tr_overload_action {
	TR_OVERLOAD_REJECT_NON_EMERGENCY_MO_DT       = 0,
	TR_OVERLOAD_REJECT_RRC_CR_SIGNALLING         = 1,
	TR_OVERLOAD_PERMIT_EMERGENCY_AND_MT_ONLY     = 2,
	TR_OVERLOAD_PERMIT_HIGH_PRIORITY_AND_MT_ONLY = 3
};

/* ---- 이벤트 종류 (번호 고정) ------------------------------------------------------ */
enum tr_event_kind {
	TR_EVENT_RRC_SETUP_REQUEST          = 1,
	TR_EVENT_RRC_REEST_REQUEST          = 2,
	TR_EVENT_RRC_RESUME_REQUEST         = 3,   /* [INACTIVE] */
	TR_EVENT_RRC_SETUP                  = 4,
	TR_EVENT_RRC_REJECT                 = 5,
	TR_EVENT_RRC_SETUP_COMPLETE         = 6,
	TR_EVENT_RRC_SMC                    = 7,
	TR_EVENT_RRC_SMC_COMPLETE           = 8,
	TR_EVENT_RRC_SMC_FAILURE            = 9,
	TR_EVENT_RRC_REEST                  = 10,
	TR_EVENT_RRC_REEST_COMPLETE         = 11,
	TR_EVENT_RRC_RESUME                 = 12,  /* [INACTIVE] */
	TR_EVENT_RRC_RESUME_COMPLETE        = 13,  /* [INACTIVE] */
	TR_EVENT_RRC_RELEASE                = 14,
	TR_EVENT_RRC_DCCH_OPAQUE            = 15,
	TR_EVENT_RRC_OTHER                  = 16,
	/* 17 은 비어 있음: F1 의 NAS 를 따로 내는 이벤트였는데 내보내는 곳을 끝내 두지 않았음.
	 *   보안 전 초기 NAS 는 RRCSetupComplete 이벤트가 payload.setup_complete.nas 로 같이 올리고,
	 *   보안 뒤의 F1 NAS 는 암호문이라 읽지 않음. 번호를 당기지 않는 이유는 42 와 같음. */
	TR_EVENT_F1_UE_CTX_SETUP            = 18,
	TR_EVENT_F1_UE_CTX_RELEASE_REQ      = 19,
	TR_EVENT_F1_UE_CTX_RELEASE_CMD      = 20,
	TR_EVENT_F1_UE_CTX_RELEASE_COMPLETE = 21,
	TR_EVENT_F1_RESET                   = 22,
	TR_EVENT_SCTP_ASSOC_END             = 23,  /* [관측자] */
	TR_EVENT_NG_INITIAL_UE_MESSAGE      = 24,
	TR_EVENT_NG_AMF_DL_UE_MSG           = 25,
	TR_EVENT_NG_NAS                     = 26,
	/* 27 은 비어 있음: NG UE CONTEXT RELEASE REQUEST(id-UEContextReleaseRequest = 42, TS 38.413)를
	 *   obs 가 내지 않아 지웠음 — obs.c 의 NP_ 목록에 그 절차가 없어 닿을 수 없었음.
	 *   번호를 당기지 않는 이유는 42 와 같음. */
	TR_EVENT_NG_UE_CTX_RELEASE_CMD      = 28,
	TR_EVENT_NG_UE_CTX_RELEASE_COMPLETE = 29,
	TR_EVENT_NG_OVERLOAD_START          = 30,
	TR_EVENT_NG_OVERLOAD_STOP           = 31,
	TR_EVENT_NG_RRC_STATE_REPORT        = 32,  /* [INACTIVE] */
	TR_EVENT_F1_UE_TRANSFER             = 33,
	/* 34 는 비어 있음: 우리가 만들려던 '망이 먼저 끊음' 이벤트인데 내는 자리를 끝내 안 두었음. */
	TR_EVENT_RRC_RECONFIG_SEC           = 35,
	TR_EVENT_F1_ALG_CHANGE_OPPORTUNITY  = 36,
	TR_EVENT_F1_CELL_CONFIG             = 37,
	TR_EVENT_NG_SETUP                   = 38,
	/* 39 는 비어 있음: NGAP ERROR INDICATION(id-ErrorIndication = 9, TS 38.413)을 obs 가 내지 않아
	 *   지웠음 — 27 과 같은 사정임. */
	TR_EVENT_OBS_UE_EVICTED             = 40,  /* [관측자] */
	TR_EVENT_OBS_UE_REPLACED            = 41,  /* [관측자] */
	/* 42 는 비어 있음: AMF CONFIGURATION UPDATE 이벤트가 있었는데 obs 가 내지도 tr 이 읽지도 않아 지웠음.
	 *   번호를 당기지 않는 이유는 위아래 값이 기록 문서와 README 에 번호로 적혀 있기 때문임. */
	TR_EVENT_RRC_MALFORMED              = 43,  /* 가시(보안 전, CCCH) RRC 디코드 실패 = 규격 밖 IE. 단말마다 */
	TR_EVENT_AP_DECODE_FAIL             = 44,  /* F1AP 및 NGAP 엔벨로프 디코드 실패. 연결 단위(단말 없음) */
	TR_EVENT_F1_INITIAL_UL              = 45,  /* INITIAL UL RRC MESSAGE TRANSFER 1건. 안에 실린 RRC 와 무관하게 메시지마다 1회 */
	TR_EVENT_F1_SETUP                   = 46,  /* F1 SETUP REQUEST 1건. DU 가 F1 을 새로 맺음 = 그 DU 의 UE 컨텍스트가 한꺼번에 사라짐 */
	TR_EVENT__COUNT                     = 47   /* 배열 크기용(0 은 쓰지 않음) */
};

/* 탐지 엔진으로 나가는 점 표기 이름("E.RRC.SETUP_REQUEST")을 돌려줌. 범위 밖이면 NULL. 출력과 시험용 */
const char *tr_event_name(enum tr_event_kind kind);

/* ---- 이벤트별 속성 ---------------------------------------------------------------- */
/* 원인 값은 표준 ENUMERATED 의 순번(0부터)을 그대로 씀. -1 = 없음 또는 모름.
 *   RRC 계열: TS 38.331 EstablishmentCause(16값), ResumeCause(16값)
 *   UECNTX 계열: TS 38.413 RRCEstablishmentCause(12값, 확장 notAvailable / mo-ExceptionData 포함) */
enum tr_ue_identity_type { TR_UE_IDENTITY_NONE = 0, TR_UE_IDENTITY_STMSI_PART1, TR_UE_IDENTITY_RANDOM };
enum tr_prior_req { TR_PRIOR_SETUP = 0, TR_PRIOR_REEST_FALLBACK, TR_PRIOR_RESUME_FALLBACK, TR_PRIOR_OTHER_OR_UNREADABLE };
enum tr_suspend { TR_SUSPEND_UNKNOWN = 0, TR_SUSPEND_NO, TR_SUSPEND_YES };
enum tr_rrc_container { TR_RRC_CONTAINER_NONE = 0, TR_RRC_CONTAINER_SRB0, TR_RRC_CONTAINER_SRB1 };
enum tr_scope { TR_SCOPE_UE = 1, TR_SCOPE_LIST, TR_SCOPE_ALL };

struct tr_bytes { const uint8_t *bytes; size_t len; };   /* 빌린 메모리 — 콜백 안에서만 유효 */

/* tr_reset_ue: 일부 RESET 이 가리킨 단말 하나.
 *   두 번호를 다 들고 오는 이유: TS 38.473 §8.2.1.2.1 이 "shall use the gNB-CU UE F1AP ID IE
 *   and/or the gNB-DU UE F1AP ID IE" 라고 적어 한쪽만 실릴 수 있음. 어느 쪽을 쓸 수 있는지는
 *   읽는 쪽마다 다름 - tr 은 DU 번호로 레코드를 찾고, 탐지 엔진 와이어(f1_evt.du_ue_ids)도
 *   DU 번호만 실을 수 있음. 가리키지 못한 항목은 읽는 쪽에서 이유별로 셈 */
struct tr_reset_ue {
	uint32_t du_ue_id;   bool has_du_ue_id;
	uint32_t cu_ue_id;   bool has_cu_ue_id;
	/* f1ue: obs 가 자기 표에서 찾아 준 그 단말의 키. valid 가 거짓이면 못 찾았다는 뜻임.
	 *   키를 같이 올리는 이유는 속도임 - 집계 쪽이 목록 항목마다 레코드를 선형 탐색하면 위조 RESET
	 *   하나로 센서를 멈춰 세울 수 있음(항목 상한 x 레코드 수). 키가 있으면 해시 한 번임 */
	struct tr_f1ue f1ue;
};

/* obs_nas_values: NAS 메시지 하나에서 꺼낸 값.
 *
 *   한 구조체를 두 자리가 씀. 두 자리에서 꺼내는 값이 같기 때문임 — F1 로 온 줄도 N2 로 온 줄도
 *   id_type, s_tmsi, cause 를 그대로 싣음.
 *
 *     F1   RRCSetupComplete 안의 초기 NAS    AS 보안 전 평문이라 obs 가 바로 읽음
 *     N2   NGAP 이 나르는 NAS-PDU            SHT 1~4 면 학습한 알고리즘으로 가시성을 판정
 *
 *   정수 칸의 -1 은 '안 읽음' 하나만 뜻함. 0 은 이 칸들에서 전부 정상값이라
 *   (SHT 0 = 평문, 알고리즘 0 = NEA0/NIA0, 신원 종류 0 = No identity, Switch off 0 = normal detach)
 *   memset 이 남긴 0 을 센티널로 쓸 수 없음 — 채우는 쪽이 손으로 적음. */
struct obs_nas_values {
	int epd;                 /* 확장 프로토콜 판별자. 해석에 실패해도 읽은 만큼 담음(libnas 계약) */
	int sht;                 /* 와이어 바깥의 보안 헤더 종류 */
	int msg_type;            /* epd 가 고른 표의 메시지 종류. 이름표에 없는 값은 담지 않음 */
	int reg_type;            /* REGISTRATION REQUEST 의 5GS 등록 유형(TS 24.501 §9.11.3.7) */
	int id_type;             /* 5GS mobile identity 의 신원 종류(표 9.11.3.4.1) */
	int switch_off;          /* DEREGISTRATION REQUEST 의 Switch off 비트(표 9.11.3.20.1) */
	int mm_cause;            /* 5GMM cause 번호(TS 24.501 §9.11.3.2) */
	bool has_stmsi48;        /* 48비트를 담았나. 신원 종류 2(5G-GUTI)와 4(5G-S-TMSI)에서만 참 */
	uint64_t stmsi48;
	/* 이 메시지가 NAS SECURITY MODE COMMAND 일 때, 그 SMC 가 고른 알고리즘.
	 *   메시지를 풀 때 쓴 알고리즘(앞선 SMC 에서 학습한 값)과는 다른 개념임. 한 칸이 둘을 겸하면
	 *   SMC 줄에 학습 이전 값(첫 SMC 면 -1)이 실려 나감 = 조용한 오값.
	 *   푸는 데 쓴 값은 obs 안에만 있으면 되므로 이벤트로 올리지 않음 */
	int smc_ciph_alg;
	int smc_integ_alg;
	bool inner_readable;           /* 보호된 메시지의 안쪽을 풀어 읽었나 */
	bool msg_type_inferred;        /* 추론한 것은 SHT 가 아니라 msg_type */
	/* sec_header_direction_ok: 보안 헤더 종류(SHT 3/4)가 규격이 정한 방향으로 왔나. 제약 없는 SHT 면 참.
	 *   방향을 아는 계층이 obs 뿐이라 거기서 판정해 넘김(표는 obs.h) — 거짓이면 보안 상태를 전진시키지 않음 */
	bool sec_header_direction_ok;
	bool non_delivered;            /* NAS NON DELIVERY INDICATION 으로 온 사본인가. F1 경로는 항상 거짓 */
	bool parse_ok;                 /* 형식이 정상이었나(malformed 구분) */
};

/* obs_event: 관측 이벤트 하나.
 *   앞쪽 12칸은 모든 이벤트에 공통인 헤더임 - 어느 단말의, 어느 인터페이스에서, 언제 일어난
 *   일이며 그 값을 얼마나 믿을 수 있는가. 뒤쪽 payload 는 이벤트 종류마다 다름 */
struct obs_event {
	enum tr_event_kind kind;
	uint64_t           wallclock_ns;   /* 벽시계 ns */
	enum tr_iface      iface;
	enum tr_direction  direction;
	uint32_t           assoc_id;       /* SCTP 연결 번호(탭 내부) */
	struct tr_f1ue     f1ue;
	struct tr_n2ue     n2ue;
	/* amf_id: N2 이벤트에서 libobs 가 매긴 AMF 키 번호((AMF Name, Served GUAMI List) 또는 임시 키).
	 *   0 = 모름 */
	uint32_t           amf_id;
	struct tr_nr_cgi   cell;
	enum tr_quality    quality;
	int16_t            rrc_chan;       /* 디코드된 RRC 의 통로(enum rrc_chan, 1~5). 0 = RRC 아님 또는 미디코드 */
	const char        *rrc_msg_name;   /* 그 RRC 의 ASN.1 타입 이름. librrc 의 고정 문자열이라 수명 제약 없음.
	                                    *   rrc_chan > 0 일 때만 유효 */
	/* 이벤트 종류마다 다른 칸. 어느 멤버가 유효한지는 위 kind 가 정하고, 오른쪽 주석이 그 kind 번호임.
	 *
	 * 아래 도메인 약어의 근거. 기억이 아니라 저장소 안 1차 출처로 확인했음 - 경로와 행을 그대로 열어 볼 수 있음.
	 *   crnti = C-RNTI. 문법 원문 asn1/nr-rrc-17.3.0.asn1:775, asn1/f1ap-18.8.0.asn:1154.
	 *           규격 대응은 asn1/README.md:11-12 (nr-rrc = TS 38.331, f1ap = TS 38.473 V18.8.0).
	 *           값 범위도 거기서 옴: RNTI-Value ::= INTEGER (0..65535).
	 *   stmsi = 5G-S-TMSI. asn1/nr-rrc-17.3.0.asn1:6829 의 NG-5G-S-TMSI ::= BIT STRING (SIZE (48))
	 *           가 stmsi48 의 48비트 근거이고, :1347-1349 의 ng-5G-S-TMSI-Part2 BIT STRING (SIZE (9))
	 *           가 stmsi_part2 의 9비트 근거임(TS 38.331). */
	union {
		struct {
			enum tr_ue_identity_type ue_identity_type;
			uint64_t ue_identity39;
			int est_cause;
			uint32_t crnti;
		} setup_request;  /* 1 */

		/* initial_ul: DU to CU RRC Container IE(선택)의 유무.
		 *   이름을 'DU 가 못 받는다' 로 짓지 않은 이유 — TS 38.473 §8.4.1.2 는 두 IE 의 논리곱으로 말함:
		 *     "If neither the DU to CU RRC Container IE nor the Sidelink Configuration Container IE in the
		 *      Sidelink Relay Configuration IE is included in the INITIAL UL RRC MESSAGE TRANSFER, the gNB-CU
		 *      should reject the UE under the assumption that the gNB-DU is not able to serve such UE."
		 *   f1ap 는 Sidelink 쪽 IE 를 뽑지 않으므로 우리가 보는 것은 앞쪽 하나뿐임. 그 하나만 담고,
		 *   '거절 예상' 이라는 판정은 이 플래그로 하지 않음 */
		struct {
			bool has_du_to_cu_rrc_container;
		} initial_ul;  /* 45 */

		/* malformed: 43, 44. reason 은 디코드 실패 코드임.
		 *   -ENOMSG = 이름 없음 또는 릴리스 드리프트, -EBADMSG = 구조적 */
		struct {
			int reason;
		} malformed;

		struct {
			uint32_t old_crnti;
			uint16_t old_pci;
			int reest_cause;
			uint32_t crnti;
		} reest_request;  /* 2 */

		struct {
			uint64_t i_rnti;
			bool i_rnti_is_full40;
			int resume_cause;
			bool ccch1;
		} resume_request;  /* 3 */

		struct {
			enum tr_prior_req prior_req;
		} setup;  /* 4 */

		/* reject: 5. has_wait_time 이 거짓이면 wait_time_s 는 뜻이 없음 - 플래그 없이 값만 들고
		 *   오면 waitTime 이 없는 RRCReject 에서 0 이 '0초 대기' 라는 뜻으로 나감.
		 *   근거 범위는 librrc 가 적은 1~16초임 */
		struct {
			bool has_wait_time;
			int wait_time_s;
			enum tr_prior_req prior_req;
		} reject;

		/* setup_complete: RRC 식별자와, 그 안에 실린 초기 NAS(AS 보안 전 평문).
		 *   has_stmsi48 이 두 겹인 것은 중복이 아님: 바깥쪽은 RRC 식별자 IE 에서, nas.has_stmsi48 은
		 *   NAS 5GS mobile identity 에서 온 같은 개념의 값이고 둘 중 하나만 실리는 경우가 있음.
		 *   RRC 줄과 NAS 줄을 각각 그 계층이 본 값으로 채우려면 두 칸이 다 있어야 함 */
		struct {
			bool has_stmsi_part2;
			uint16_t stmsi_part2;
			bool has_stmsi48;
			uint64_t stmsi48;
			struct obs_nas_values nas;
		} setup_complete;  /* 6 */

		/* smc: 7, 35. RRC SecurityModeCommand 와 RRCReconfiguration 이 고른 알고리즘.
		 *   이름을 값과 같이 들고 오는 이유: 출력 층은 번호가 아니라 이름을 내보냄("nea0", "nia2").
		 *   번호만 내려보내면 출력 층이 이름표를 따로 들어야 하고, 문법 판이 바뀌면 그 손표가 조용히
		 *   틀림. 같은 결함을 F1AP Cause 에서 겪어 이름 포인터를 들고 내려오는 것으로 고쳤음.
		 *   librrc 의 고정 문자열이라 rrc_release 뒤에도 유효하므로 포인터만 들고 옴.
		 *   모르는 값이면 NULL - 그때는 알고리즘을 생략하고 셈. 이름을 만들지 않음 */
		struct {
			int ciph_alg;
			int integ_alg;
			const char *ciph_alg_name;
			const char *integ_alg_name;
		} smc;

		struct {
			enum tr_suspend suspend;
			bool after_sec;
		} release;  /* 14 */

		struct {
			int srb_id;
		} dcch_opaque;  /* 15 */

		struct {
			int rrc_chan;
			const char *rrc_msg_name;
		} rrc_other;  /* 16 */

		/* nas: 17, 26. N2 가 나르는 NAS-PDU 하나 */
		struct obs_nas_values nas;

		struct {
			uint32_t crnti;
			bool has_crnti;
			enum tr_ap_outcome outcome;
		} ue_ctx_setup;  /* 18 */

		/* f1_release 의 세 칸에 대한 계약.
		 *   cause_present: Cause IE 가 실제로 실려 있었나. 없으면 cause_group 과 cause_value 는
		 *     f1ap.c init_msg 의 센티널 -1 이 그대로 남아 있고, 그걸 내보내면 "group-1:value-1" 이라는
		 *     없는 값을 지어냄. has_old_du_ue_id(= old gNB-DU UE F1AP ID IE 유무)는 Cause 와 무관하므로
		 *     Cause 출력의 관문으로 쓰면 양방향으로 틀림.
		 *   cause_group_name 과 cause_value_name: 같은 Cause 의 ASN.1 이름("radioNetwork", "normal-release").
		 *     들고 내려오는 이유: 탐지 엔진 와이어가 번호가 아니라 이름을 받음("radioNetwork:normal-release").
		 *     번호만 내려보내면 출력 층이 이름을 지어낼 수밖에 없고, 실제로 "group2:value6" 이 나갔음.
		 *     ap.h 의 그 이름은 고정 문자열이라 f1ap_release 뒤에도 유효하므로 포인터만 들고 옴.
		 *     모르는 값이면 NULL - 그때는 Cause 를 생략하고 셈. 이름을 만들지 않음 */
		struct {
			int cause_group;
			int cause_value;
			bool cause_present;
			const char *cause_group_name;
			const char *cause_value_name;
			bool has_old_du_ue_id;
			enum tr_rrc_container rrc_container_kind;
		} f1_release;  /* 19, 20 */

		/* reset: 22, 46.
		 *   F1 SETUP 이 RESET 과 같은 칸을 쓰는 이유: F1 SETUP 은 F1 인터페이스 (재)초기화이고
		 *   (TS 38.473 §8.2.3), 받는 쪽의 UE 컨텍스트를 전부 지움 — RESET(전체)과 같은 효과임.
		 *   cells 와 ues 는 빌려 쓰는 포인터임. 콜백이 돌아가는 동안만 유효함. */
		struct {
			enum tr_scope scope;                 /* SETUP 은 늘 TR_SCOPE_ALL */
			const struct tr_nr_cgi *cells;
			int cell_count;
			bool cells_known;                    /* 거짓 = 그 DU 의 셀을 모름. 읽는 쪽은 '모든 셀' 로 봄 */
			const struct tr_reset_ue *ues;       /* 일부 RESET 이 가리킨 UE. 읽는 쪽마다 쓸 수 있는 번호가 다름 */
			int ue_count;
			int ue_overflow_count;               /* 상한을 넘겨 목록에 못 실은 UE */
		} reset;

		struct {
			uint32_t old_du_ue_id;
			int srb_id;
		} ue_transfer;  /* 33 */

		/* initial_ue: 24. NAS 는 RRCSetupComplete 과 같은 바이트라 libobs 가 계수기만 올림 */
		struct {
			int est_cause;
		} initial_ue;

		struct {
			int proc_code;
			bool has_amf_ue_ngap_id;
			bool first_for_ran_ue_ngap_id;
		} amf_dl;  /* 25 */

		struct {
			int cause_group;
			int cause_value;
		} ng_cause;  /* 27, 28, 34, 39 */

		struct {
			uint32_t action_mask;
			int traffic_load_reduction_pct;
			bool nssai_list_present;
			bool has_action;
		} overload;  /* 30 */

		struct {
			int rrc_state;
		} rrc_state_report;  /* 32 */

		struct {
			struct tr_bytes amf_name;
			uint64_t guami_digest;
			bool ue_contexts_retained;
			bool outcome_failure;
		} ng_setup;  /* 38, 42 */
	} payload;
};
#endif /* TELEMETRY_TYPES_H */
