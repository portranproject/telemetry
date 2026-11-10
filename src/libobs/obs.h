/**
 * obs.h
 * : libobs 공개 계약 - SCTP 메시지를 넣으면 관측 이벤트가 콜백으로 나옴
 *
 * [1] 역할
 *
 *     단말 표(F1, N2) 유지, 암호화로 못 읽는 구간 판정, F1 과 N2 짝짓기,
 *     AMF 와 DU 에 우리 번호 매기기
 *     단, TS 28.552 셈 규칙, 주기 집계, 추론 규칙 - 전부 libtelemetry 몫
 *
 * [2] 부르는 순서. 시간을 먼저 진행해야 함.
 *
 *     obs_new() -> [ obs_advance(t) -> obs_on_sctp(msg) ] 반복 -> obs_free()
 *
 *     obs_advance 를 건너뛰면 수명 만료와 유예 처리가 밀려, 이미 끝난 단말이 표에 남을 수 있음.
 *
 * [3] 소유권. obs_new 가 만든 것은 obs_free 가 품음.
 *     콜백으로 넘기는 이벤트와 그 안의 바이트는 콜백이 돌아올 때까지만 유효함 - 뒤에도 쓰려면 복사할 것.
 *
 * [4] 스레드 하나. 같은 obs 를 여러 스레드에서 부르지 않음.
 *
 * [5] 계수기가 기능임. 우리는 참여자가 아니라 수동 관측자라 못 읽은 것을 다시 달라고 할 수 없음.
 *     그래서 못 읽었다는 사실을 남기지 않으면 '상대가 안 보냈음' 과 '우리가 못 읽었음' 이 같은
 *     모양이 되고, 지표가 조용히 거짓이 됨. 아래 obs_stats 가 그 장부임 - 버린 이유마다 칸이 따로 있고,
 *     뜻이 정반대인 둘을 한 칸에 합치지 않음.
 */
#ifndef TELEMETRY_OBS_H
#define TELEMETRY_OBS_H

#include <common/types.h>
#include <libsctp/sctp.h>

/* DTLS/SCTP 를 쓰는 F1-C, NG-C 의 PPID. libsctp 는 이 둘로 분기하지 않으므로(해독할 수 없음) 여기에 둠.
 * libobs 는 이 PPID 를 본 횟수만 obs_stats.dtls_seen_count 에 남김 — '암호화돼 못 읽은 구간이 있었음' 은
 * 블라인드 신호이고, 그것을 세지 않으면 계측 공백이 '트래픽이 없었음' 과 같은 모양이 됨.
 *   F1AP: "the ppid ... for the application layer protocol F1AP is 62, and 68 for DTLS over SCTP" (TS 38.472 §7)
 *   NGAP: "the ppid ... for the application layer protocol NGAP is 60, and 66 for DTLS over SCTP" (TS 38.412 §7) */
#define OBS_PPID_NGAP_DTLS 66
#define OBS_PPID_F1AP_DTLS 68

/* obs_cfg: 표 상한과 시간 창. 0 이면 괄호 안 기본값을 씀.
 *   구현이 실제로 읽는 칸만 둠 - 안 읽는 칸을 공개 계약에 두면 호출자가 설정했다고 믿는데 효과가 없음. */
struct obs_cfg {
	uint32_t ue_capacity;                 // F1 단말 표 상한 (131072)
	uint32_t n2_capacity;                 // N2 단말 표 상한 (= ue_capacity)
	uint32_t assoc_capacity;              // SCTP 연결 해시 상한 (1024)
	uint32_t ue_ttl_s;                    // CONNECTED, INACTIVE, half_open 이 아닌 레코드 정리 (600)
	uint32_t n2_release_grace_s;          // RELEASE COMMAND 뒤 COMPLETE 대기 (5)
	uint32_t correlation_window_ms;       // F1 과 N2 짝짓기 시간창 (100)
	uint32_t corr_queue_per_cell_capacity;  // 셀별 짝 대기열 상한 (16384)
	/* dl_dcch_exempt_max_count: AS 보안 전 평문 NAS 를 나르는 DCCH(DLInformationTransfer 등)를
	 *   가시로 볼 상한 (16). EAP-TLS, EAP-AKA' 처럼 인증이 길어지는 경우를 받기 위한 것이고,
	 *   넘으면 거짓 가독을 막으려고 가시성 관문을 닫음. 255 로 클램프함 */
	uint32_t dl_dcch_exempt_max_count;
};

/* obs_stats: 관측기 계측. 실제로 채워지는 칸만 공개함 - 0 으로 고정된 칸을 공개하면 유실 신호를
 *   조용히 깎음(읽는 쪽이 '그 일이 없었다' 로 읽기 때문). */
struct obs_stats {
	// F1 과 N2 짝짓기 결과. 모호(후보 둘 이상)는 짝을 짓지 않고 세기만 함
	uint64_t corr_unique_count, corr_ambiguous_count;
	uint64_t corr_unmatched_f1_count, corr_unmatched_n2_count, corr_expired_count;
	uint64_t corr_queue_overflow_count;

	// 단말 표에서 레코드가 사라진 이유
	uint64_t ue_evicted_count, ue_replaced_count, du_id_reuse_count;

	/* f1_reset_removed_count: F1 RESET 또는 F1 SETUP 으로 우리 표에서 지운 F1 레코드 수.
	 *   안 지우면 다음 단말이 같은 du_ue_id 로 올 때 옛 레코드의 AS 보안 상태로 가시성 관문을
	 *   판정함 = 조용한 오값. N2 쪽 짝은 ng_reset_removed_count 임 */
	uint64_t f1_reset_removed_count;
	/* ng_reset_removed_count: NG RESET(reset-all)로 지운 N2 레코드 수.
	 *   TS 38.413 §8.7.4.2.1 상 리셋 뒤 양쪽이 UE 연결을 전부 해제하므로, 그 뒤 같은
	 *   RAN-UE-NGAP-ID 는 재사용이지 '옛 종료를 놓친 것' 이 아님 */
	uint64_t ng_reset_removed_count;

	/* f1_grace_expired_count 와 n2_grace_expired_count: RELEASE COMMAND 를 본 뒤 유예 안에
	 *   COMPLETE 를 못 봐 종료 이벤트를 합성한 레코드 수. 한 칸으로 합치면 'N2 쪽 해제 관측 구멍' 과
	 *   'F1 쪽 해제 관측 구멍' 이 구별되지 않는데, 두 구멍은 탭 위치가 서로 달라 원인이 다름 */
	uint64_t f1_grace_expired_count, n2_grace_expired_count;

	/* amf_key_table_full_count: AMF 키 표(32칸)가 꽉 차 번호를 못 매긴 NG SETUP RESPONSE 수.
	 *   그 연결의 N2 이벤트는 amf_id = 0 으로 나가고 집계 쪽이 연결 번호로 대리함 */
	uint64_t amf_key_table_full_count;
	/* f1_setup_ambiguous_count: F1 SETUP REQUEST 를 봤는데 어느 F1-C 인스턴스인지 못 가린 수.
	 *   gNB-DU ID 가 없거나, 같은 연결에 다른 번호가 온 공유 TNL(TS 38.473 §8.2.3.1 NOTE).
	 *   그 판은 닫을 범위를 추측하지 않고 셈 */
	uint64_t f1_setup_ambiguous_count;
	/* assoc_table_full_count: 연결 해시가 꽉 차 새 SCTP 연결의 DU 매핑을 만들지 못한 횟수.
	 *   그 연결의 단말은 임시 DU 키로 떨어짐 */
	uint64_t assoc_table_full_count;

	/* dcch_gate_closed_on_cap_count: 인증이 길어져 DCCH 면제 상한을 넘겨 가시성 관문이 닫힌 횟수.
	 *   SMC 를 놓친 것과 구별하려고 따로 셈 */
	uint64_t dcch_gate_closed_on_cap_count;
	/* dtls_seen_count: DTLS(Datagram Transport Layer Security)-over-SCTP 로 온 F1 또는 N2 를 본 수
	 *   (PPID 66, 68). 제어평면이 통째로 불가시라는 뜻임. DTLS 복호는 이 제품의 범위가 아니지만,
	 *   ESP(esp_seen_count)와 같이 '못 본 구간이 있었다' 는 신호로 세어 obs_internal_loss 로 올림 */
	uint64_t dtls_seen_count;

	/* direction_unknown_count: 방향을 절차로도 와이어 포트로도 못 정한 메시지 수.
	 *   종전에는 그런 경우에도 UP 을 추측해 실었음 */
	uint64_t direction_unknown_count;
	/* direction_conflict_count: 절차가 정한 방향과 와이어 포트 규칙이 어긋난 수. 둘 다 알 때만 셈.
	 *   관측 지점(루프백, 비표준 포트)의 문제이거나 상대의 비정상 신호임 */
	uint64_t direction_conflict_count;

	/* ap_body_unknown_count: 문법에 없는 (절차, PDU 종류) 또는 PDU CHOICE 의 확장 갈래인
	 *   F1AP, NGAP PDU 수. 이벤트를 내지 않음. 깨진 본체는 디코드 실패라 malformed 이벤트로 감.
	 *   종전에는 절차 번호만 보고 RESET(전체)과 OVERLOAD 이벤트를 냈음 */
	uint64_t ap_body_unknown_count;

	// NGAP IE 를 담지 못한 이유. 네 칸을 합치지 않는 이유는 원인마다 할 일이 다르기 때문임
	uint64_t ngap_unknown_ie_count;       /* 문법이 모르거나 그 메시지에 없어 asn1c 가 버린 IE 수.
	                                       *   0 이 아니면 상대가 새 판이거나 그 메시지에 정의되지 않은
	                                       *   IE 를 실은 송신임(TS 38.413 §10.3) */
	uint64_t ngap_rejected_ie_count;      // 값이 규격 범위 밖이거나 모르는 열거 확장값
	uint64_t ngap_duplicate_ie_count;     // 담는 IE 가 한 메시지에 두 번 이상 옴(TS 38.413 §10.3.6 위반)
	uint64_t ngap_type_mismatch_ie_count; /* IE 번호는 아는데 값 타입이 표와 다름. 0 이 아니면 상대가
	                                       *   새 판이거나 타입을 바꾼 조작 PDU 임 */

	/* nas_malformed_count: nas_parse 가 형식 오류로 돌려보낸 NAS-PDU 수. F1, N2 세 호출 지점의 합.
	 *   아래 세 칸(truncated, epd_mismatch, reserved_sht)의 합과 같음 - 이쪽은 커버리지 판정이 읽는
	 *   총계이고 아래 셋은 원인별 분해임. 원인이 서로 다른 행동을 부르므로 합치지 않음 */
	uint64_t nas_malformed_count;
	/* nas_truncated_count: 길이가 모자라 헤더조차 못 읽은 수. 우리 캡처 손실이 아니라 상대가 정한
	 *   길이임 - 잘린 SCTP 청크는 libsctp 가 부분 조각에서 멈춰 디코더에 닿지 않기 때문임 */
	uint64_t nas_truncated_count;
	/* nas_epd_mismatch_count: 바깥 EPD 가 5GMM, 5GSM 둘 다 아니거나, 보호된 메시지의 안쪽 EPD 가
	 *   5GMM 이 아닌 수. 후자는 5GSM 만이 아니라 비-5GMM 전부임(안쪽 분기가 5GMM 하나만 통과시킴).
	 *   규격상 있을 수 없는 조합이라 조작의 증거임 — TS 24.501 §8.2.28.1 :
	 *   "This message is sent by the UE or the network to transfer a plain 5GS NAS message
	 *   as specified in subclause 8.2" (§8.3 의 5GSM 은 안쪽에 못 옴) */
	uint64_t nas_epd_mismatch_count;
	/* nas_reserved_sht_count: TS 24.501 표 9.3.1 이 "All other values are reserved." 로 둔
	 *   보안 헤더 종류(5~15) 수. 조작이거나 우리보다 새 판임 */
	uint64_t nas_reserved_sht_count;
	/* nas_unknown_msg_type_count: EPD 가 고른 표(TS 24.501 표 9.7.1 / 9.7.2)에 없는 메시지 타입이라
	 *   담지 않은 수. 0 이 아니면 상대가 새 판이거나 이름공간이 어긋난 조작 PDU 임 */
	uint64_t nas_unknown_msg_type_count;
	/* nas_missing_mandatory_ie_count: 필수 IE(M V, M LV-E)가 길이 밖이라 못 읽은 수
	 *   (TS 24.501 §7.5.1 의 원인 #96 갈래). 이름까지 붙은 메시지에서 그 IE 가 '없었음' 과
	 *   '못 읽었음' 을 가리는 유일한 수단임 */
	uint64_t nas_missing_mandatory_ie_count;
	/* nas_rejected_ie_count: IE 는 아는데 값이 규격 범위 밖이라 담지 않은 수(예약 알고리즘 코드값,
	 *   길이가 어긋난 5G-GUTI). 담으면 `확신 있는 오값` 이 됨 */
	uint64_t nas_rejected_ie_count;
	/* nas_ie_scan_aborted_count: 선택 IE 가 선언한 길이가 메시지 끝을 넘어 주사를 끝내지 못한 수.
	 *   그 뒤에 5G-GUTI 가 있었어도 보지 못함 */
	uint64_t nas_ie_scan_aborted_count;
	/* nas_unknown_tlve_iei_count: 번호대 0x70~0x7F 인데 그 메시지 표에 TLV-E 로 없어
	 *   TS 24.501 §9.11.1 타입 4 로 건너뛴 IE 수. 값을 담은 채로도 오르므로 '버린 이유' 가 아니라
	 *   별도 관측임 - 0 이 아니면 상대가 새 판이라 IE 걸음이 어긋나고 있다는 뜻임 */
	uint64_t nas_unknown_tlve_iei_count;
	/* nas_inner_not_plain_count: 보호된 NAS 의 안쪽 보안 헤더 종류가 0 이 아닌 수.
	 *   TS 24.501 §8.2.28.1 은 안쪽을 "a plain 5GS NAS message" 로 정하고 표 9.3.1 은 평문을
	 *   0000 으로 정함. 그 판의 옥텟 3 은 메시지 타입일 수도 MAC 첫 옥텟일 수도 있어 바이트로는 못 가림 */
	uint64_t nas_inner_not_plain_count;
	/* nas_direction_mismatch_count: 메시지 타입이 규격상 올 수 없는 방향으로 온 수.
	 *   TS 24.501 §7.4 NOTE 가 방향이 어긋난 타입을 '정의되지 않은 타입' 으로 보라고 하므로 담지 않음.
	 *   담으면 단말이 하행 전용 메시지를 상행으로 보내 5GMM 주상태를 조작할 수 있음 */
	uint64_t nas_direction_mismatch_count;
	/* nas_direction_unjudged_count: 방향을 못 정해 위 판정을 하지 못한 수.
	 *   위가 '상대가 규격 밖' 이라면 이쪽은 '우리가 눈이 먼 것' 임 - 뜻이 정반대라 합치지 않음 */
	uint64_t nas_direction_unjudged_count;
	/* nas_smc_learn_skipped_count: SECURITY MODE COMMAND 모양의 NAS 가 왔는데 하행, 보안 헤더 종류 3
	 *   이 아니어서 암호 알고리즘을 학습하지 않은 수. 학습했으면 그 단말이 자기 암호문을 평문으로
	 *   읽히게 만들 수 있음. 왜 아니었는지는 아래 두 칸이 가림 - 행동 한 칸과 이유 두 칸으로 나눠야
	 *   상대의 행위와 우리의 한계를 되짚을 수 있음 */
	uint64_t nas_smc_learn_skipped_count;
	/* 보안 헤더 종류가 규격상 올 수 없는 방향으로 온 수와, 방향을 못 정해 판정하지 못한 수.
	 * TS 24.501 표 9.3.1 NOTE 1, 2 가 종류 3 을 SECURITY MODE COMMAND 에만, 종류 4 를
	 * SECURITY MODE COMPLETE 에만 묶고, 두 메시지는 각각 한 방향뿐임
	 * (§8.2.25.1 "Direction: network to UE", §8.2.26.1 "Direction: UE to network").
	 *
	 *            종류 3       종류 4
	 *   하행      정상         mismatch
	 *   상행      mismatch     정상
	 *   미상      unjudged     unjudged
	 *
	 * 뜻이 정반대라 합치지 않음 — 앞은 `상대가 조작한 것`, 뒤는 `우리가 방향을 못 정한 것` 임.
	 * 읽는 쪽이 셋임: 암호 알고리즘 학습(종류 3), 타입 추론(종류 4), 그리고 tr 의 NAS 보안 상태 전이.
	 * 방향을 아는 계층이 여기뿐이라 판정도 계수도 여기서 한 번만 함 */
	uint64_t nas_sec_header_direction_mismatch_count;
	uint64_t nas_sec_header_direction_unjudged_count;
	/* nas_pdu_absent_count: NAS-PDU 가 필수인 절차인데 그 IE 가 없던 수. IE 컨테이너가 SEQUENCE OF 라
	 *   asn1c 가 mandatory 를 강제하지 못해 도달 가능함. 세지 않으면 '상대가 NAS 를 안 실었음' 이
	 *   '그런 절차가 없었음' 과 같은 모양이 됨 */
	uint64_t nas_pdu_absent_count;
	/* rrc_state_report_no_ie_count: RRC INACTIVE TRANSITION REPORT 가 왔는데 RRCState IE 를 못 읽은 수.
	 *   ASN.1 상 mandatory 라 정상 망에선 0 이어야 함 - 0 이 아니면 디코더 판본 차이나 기형 입력
	 *   신호임. 상태를 지어내지 않고 그 수만 셈 */
	uint64_t rrc_state_report_no_ie_count;

	/* RRC 컨테이너를 풀지 못한 이유. 이유마다 따로 셈 — 합치면 원인을 되짚을 수 없음.
	 *   세지 않으면 "DU 가 안 보냈음" 과 "우리가 못 풀었음" 이 같은 모양이 됨.
	 *   앞의 두 칸은 obs_internal_loss 에 넣지 않음. 빠뜨린 것이 아니라, CU 도 버리거나 애초에 RRC
	 *   메시지가 아니어서 놓친 상태 변화가 없기 때문임. 셋째는 반대로 진짜 맹점이라 유실에 들어감. */
	uint64_t cu_ignored_container_count;   // 망 공유용 RRCSetupComplete 컨테이너. CU 가 무시하므로 우리도 버림
	uint64_t non_rrc_container_count;      // DU 가 만든 CellGroupConfig. RRC 메시지가 아님
	uint64_t unknown_rrc_channel_count;    /* librrc 의 채널 규칙 표에 없는 조합(SRB ID 없음, 범위 밖,
	                                        *   모르는 절차). 종전에는 모르는 절차를 DL-DCCH 로 짐작해
	                                        *   `조용한 오값` 이었음 */

	/* 보존 검산 — 입력 하나가 어디로 갔는지 되짚는 네 칸.
	 *   검산식    sctp_message_count == handled_no_event_count + unknown_ppid_count
	 *                                  + (이벤트를 낸 입력 수) + (위의 이유별 버린 수)
	 *   왜 필요했나: 종전에는 obs_on_sctp 가 0(처리함)을 돌려주면서 이벤트도 계수기도 안 남기는
	 *     길이 있었음. 실측에서 입력 569건 중 110건이 그 길로 갔음. 그 110건은 대부분 정상이지만
	 *     (libobs 에 그 절차 처리가 없는 메시지 12종), 정상인 것과 조용히 버린 것이 와이어에서
	 *     같은 모양이라 절차 코드만 바꾼 조작 입력이 구별되지 않고 사라졌음. */
	uint64_t sctp_message_count;      // obs_on_sctp 로 들어온 수. 검산식의 좌변
	uint64_t event_emitted_count;     // 콜백을 부른 수(시간 구동 이벤트 포함). 검산식의 우변
	uint64_t handled_no_event_count;  /* 아는 절차라 끝까지 처리했으나 낼 이벤트가 없었음. 정상임 —
	                                   *   unknown_ppid_count 와 합치지 말 것(앞은 정상, 뒤는 관측 구멍) */
	/* ue_ctx_setup_failure_cause_dropped_count: UE CONTEXT SETUP FAILURE 를 봤으나 그 Cause 를 실을
	 *   칸이 ue_ctx_setup 페이로드에 없어 버린 수. 형제인 f1_release 는 같은 Cause 를 번호와 이름
	 *   둘 다 보존함 - 형제 비대칭이라 칸을 늘리는 것이 맞으나, 그것은 와이어 계약 변경이라 지금은
	 *   버린 사실만 남김 */
	uint64_t ue_ctx_setup_failure_cause_dropped_count;
	uint64_t unknown_ppid_count;      /* F1AP, NGAP, DTLS 어느 것도 아닌 PPID 라 해석하지 않았음.
	                                   *   0 이 아니면 그 SCTP 연결에 우리가 모르는 것이 흐르고 있다는 뜻임 */
};

struct obs;
typedef void (*obs_event_cb)(void *user_ctx, const struct obs_event *event);

// 실패하면 NULL(메모리 부족). obs_cfg 의 0 칸은 기본값으로 대체함(범위 검증은 호출자 책임).
struct obs *obs_new(const struct obs_cfg *obs_cfg, obs_event_cb on_event, void *user_ctx);
/* 시간 진행: 수명 만료, 유예 만료, 짝 시간창 만료를 처리하고 그에 따른 이벤트를 냄
 *   (예: TR_EVENT_OBS_UE_EVICTED). 시각은 줄어들지 않아야 함. */
void obs_advance(struct obs *obs, uint64_t now_ns);
/* SCTP 메시지 하나(PPID 62 = F1AP, 60 = NGAP. 그 밖은 계수만).
 *   0 = 처리, 음수 = 해석 실패(계측됨, 이벤트 없음). */
int  obs_on_sctp(struct obs *obs, const struct sctp_message *sctp_message);
// SCTP 연결 시작과 끝 알림(TR_EVENT_SCTP_ASSOC_END 의 원천).
void obs_on_assoc(struct obs *obs, const struct sctp_assoc_event *assoc_event);
const struct obs_stats *obs_get_stats(const struct obs *obs);
/* 관측자 내부 유실의 합(짝 대기열 넘침 + 단말 축출 + 불가시 구간). 호출자가 이 값을 커버리지로
 *   libtelemetry 에 공급함 — 합을 내는 공식을 한 곳에 두려고 함수로 공개함. */
uint64_t obs_internal_loss(const struct obs *obs);
void obs_free(struct obs *obs);

/* 시험 전용 방향 판정: 절차 판정 -> 와이어 IANA 포트 규칙 순서를 프로덕션과 같은 코드로 노출함.
 *   pdu_type = 1 initiating / 2 successful / 3 unsuccessful.
 *   src_port 와 dst_port 가 둘 다 0 이면 와이어 단계는 미상. 프로덕션에서는 쓰지 않음.
 *   pdu_type 이 열거형이 아니라 int 인 이유: 공개 헤더는 디코더 열거형(libap 의 ap_pdu_type)을
 *   들이지 않기 때문임. */
enum tr_direction obs_direction_for_test(enum tr_iface iface, long proc_code, int pdu_type,
                                         uint16_t src_port, uint16_t dst_port);
#endif /* TELEMETRY_OBS_H */
