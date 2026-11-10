/**
 * main.c
 * : portran 로더 - 모듈 다섯을 콜백으로 잇고, 폴링 루프를 돌리고, 수명과 종료를 관리함
 *
 * [1] 전체 모양. 프로토콜 로직은 이 파일에 없음 - 계산과 판정은 전부 라이브러리 몫임.
 *
 *     커널                        main.c                     라이브러리가 하는 일
 *
 *     tcx 훅 (cap.bpf.c)
 *       |  링 버퍼
 *       v
 *     cap_poll(200ms) ------->  on_record
 *                                  |  tr_set_capture_alive
 *                                  |  obs_advance -> tr_advance      <- 시간 먼저, [3]
 *                                  v
 *                               sctp_input ----> libsctp      조각 재조립, 중복 TSN 판정
 *                                                   |
 *                 on_message  <---------------------+         완성된 메시지
 *                 on_assoc    <---------------------+         연결 생성과 소멸
 *                                  |
 *                                  v
 *                               obs_on_sctp ---> libobs       F1AP/NGAP/RRC/NAS 해석,
 *                                                   |           F1 과 N2 매칭
 *                 on_obs      <---------------------+         관측 이벤트 하나
 *                                  |
 *                                  +-> tr_on_event -> libtelemetry  셀 카운터 집계와
 *                                                        |             탐지 줄 세 가지로 변환
 *                                                        v
 *                                                     libsink       JSON Lines 한 줄로 쓰고 소켓에 보냄
 *
 *     struct pipeline 이 그 다섯 핸들을 한 벌로 묶고, 모든 콜백의 user_ctx 로 그 포인터를 넘김.
 *
 * [2] 조립은 아래에서 위로. 아래 계층이 위 계층의 생성 인자이기 때문임.
 *
 *     sink -> tr -> obs -> sctp -> cap
 *
 *     cap_open 이 마지막인 이유: 그것만이 커널에 탭을 붙이는 호출이라, 그 전에 실패하면
 *     커널에 아무것도 남기지 않고 끝낼 수 있음.
 *
 * [3] 시간을 먼저 t 까지 진행한 뒤 메시지를 넣음. 순서를 바꾸면 주기 경계가 어긋남.
 *
 *     tr_set_capture_alive(t) -> obs_advance(t) -> tr_advance(t) -> sctp_input(record)
 *                                                      |
 *                                                   여기서 주기가 닫힘
 *
 *     생존 통지가 tr_advance 보다 늦으면 사건이 든 주기가 전부 capture_alive=false 로 닫혀
 *     카운터가 null 로 나감(2026-11-09 AWS 실측: RRCSetupRequest 40건이 전부 null 주기였음).
 *
 * [4] 종료 코드 세 갈래. 감시 프로세스가 '재시작할 상황' 과 '지표를 하한으로 읽을 상황' 을
 *     가려야 하므로 섞지 않음.
 *
 *     0   정상
 *     1   운영 실패         탭 오류, 커널 통계 못 읽음, 출력 스트림 쓰기 실패
 *     2   커버리지 불완전   측정은 돌았으나 못 본 구간이 있음
 *
 * [5] 사용법.
 *
 *     sudo ./build/portran [옵션] f1:<interface_name> n2:<interface_name> ...
 *       두 역할을 다 적어야 함. 한쪽을 빼먹으면 그 인터페이스의 지표가 0 으로 나가고, 그 0 은
 *       '그 구간에 사건이 없었다' 와 같은 모양이라 빠뜨린 것을 알 수 없음.
 *       F1 과 N2 가 같은 NIC 로 흐르면 같은 이름을 두 역할에 적음 - 탭은 한 번만 붙임.
 *       같은 NIC 를 두 번 붙이면 cap_open 이 -EEXIST 로 거부하고, 거부하지 않더라도 패킷이
 *       두 번 잡힘. 최대 MAX_INTERFACES 개.
 *       접두사는 '거기에 그것이 흐른다' 는 선언이고, 올라온 메시지를 F1AP 와 NGAP 로 가르는
 *       것은 SCTP PPID 임(62 F1AP, 60 NGAP, 68/66 은 그 둘의 DTLS). 선언이 실제와 어긋나면
 *       종료 보고가 지적하고, 선언한 쪽을 한 건도 못 봤으면 커버리지 불완전으로 끝냄.
 *
 *       -g <gp_ms>                      보고 주기 ms (기본값 단일출처는 tr.h)
 *       --sock <socket_path>            탐지 엔진이 듣는 유닉스 소켓
 *       --record <file_path|->          보낸 줄을 그대로 남길 파일(- = stdout). 형식 확인용
 *       --node <node_id>                접속 인사의 node_id
 *
 *     Ctrl+C 한 번이면 부착을 풀고 링 버퍼에 남은 레코드를 마저 처리한 뒤 마지막 미완 주기를
 *     닫음. 두 번이면 남은 처리를 건너뜀.
 */
#include <errno.h>              // errno: 소켓 연결 실패 사유
#include <net/if.h>             // if_nametoindex: 레코드의 인터페이스 번호를 선언한 이름과 맞춤
#include <signal.h>             // sigaction: Ctrl+C(SIGINT) 및 SIGTERM
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>             // calloc, free, strtoull
#include <string.h>             // strcmp, strlen, memcpy, strerror
#include <time.h>               // clock_gettime: 레코드가 없는 동안에도 시간을 진행시킴
#include <unistd.h>             // close

#include <libcap/cap.h>
#include <libsctp/sctp.h>
#include <libobs/obs.h>
#include <libtelemetry/tr.h>
#include <libsink/sink.h>

#define MAX_INTERFACES 8        // 인터페이스 수 상한. CU 한 대의 F1/N2 NIC 는 보통 1~2 개임

/* RECORD_MAX_BYTES: --record 로 남기는 파일의 상한. 디스크를 채우지 않으려고 둠 - 넘으면 출력 층이
 *   녹화만 멈추고 소켓 전송은 이어감(sink.h). 1 GiB 는 sink.h 가 적은 셀 하나 1시간 약 23 MB 기준으로
 *   약 46 셀-시간이라, 형식 확인용 녹화가 이 값에 닿는 일은 없음 */
#define RECORD_MAX_BYTES (1024ull * 1024ull * 1024ull)

/* 명령행으로 선언한 인터페이스 한 칸.
 *   플래그를 둘로 나눠 두는 이유: 같은 NIC 에 F1 과 N2 가 같이 흐르는 배치가 있어서 한 칸이 두
 *     역할을 다 가질 수 있음. 역할 하나만 담는 칸으로 두면 그 배치를 적을 수 없음.
 *   두 계수기를 함께 두는 이유: 선언은 운영자의 주장이고 PPID 가 사실임. 둘을 한 칸에 모아 두면
 *     종료 보고가 그 자리에서 대조함 */
struct declared_interface {
	const char *interface_name;   // argv 를 그대로 가리킴. 프로세스가 끝날 때까지 살아 있어 복사하지 않음
	uint32_t interface_index;     // cap_record.interface_index 와 맞춰 보는 커널 번호
	bool is_f1_declared;
	bool is_n2_declared;
	uint64_t f1ap_message_count;  // 이 NIC 에서 PPID 62 로 올라온 SCTP 메시지 수
	uint64_t ngap_message_count;  // 같은 NIC 에서 PPID 60 으로 올라온 수
};

/* 파이프라인 한 벌. 모든 콜백의 user_ctx 가 이 구조체를 가리킴 */
struct pipeline {
	struct cap *cap;                // 캡처(커널 탭). 커버리지 통계를 여기서 읽음
	struct sctp_ctx *sctp;
	struct obs *obs;
	struct tr *tr;
	struct sink *sink;
	/* 명령행으로 선언한 인터페이스 표. main 의 지역 배열을 빌려 씀(main 보다 오래 살지 않음).
	 *   메시지가 올 때마다 NIC 별 PPID 계수기를 올리는 자리라 콜백에서 닿아야 함 */
	struct declared_interface *declared_interfaces;
	int declared_interface_count;
	uint64_t last_capture_time_ns;  // 마지막으로 본 레코드의 시각. tr_finish 의 끝 시각으로 씀
	                                //   라이브러리에 "지금 몇 시냐" 를 묻지 않음 - 관측한 시각만 씀

	/* 마지막으로 성공한 커널 통계 읽기의 사본. cap_get_stats 는 하나라도 못 읽으면 출력을 0 으로
	 *   비우므로, 그 0 을 올리면 누적값이 뒤로 가 이 주기가 '깨끗' 으로, 다음 주기가 '전 구간 유실'
	 *   로 보고됨. 실패하면 이 사본을 재사용해 단조성을 지킴 */
	struct cap_stats last_cap_stats;
	uint64_t cap_stats_error_count;  // cap_get_stats 실패 횟수. 0 이 아니면 커버리지가 불완전함
};

static volatile sig_atomic_t stop_signal_count = 0;   // Ctrl+C 횟수. 1 = 정리하고 끝냄, 2 = 남은 처리도 건너뜀
static void on_signal(int signal_number) { (void)signal_number; stop_signal_count++; }

/* feed_coverage: 캡처와 전송계층이 놓친 양을 libtelemetry 로 올려 보고 헤더의 유실 지표를 채움.
 *   이유: 조용히 0 으로 두면 '못 본 게 있는 구간' 과 '깨끗한 구간' 이 같은 모양이 됨. 우리는
 *     수동 관측자라 다시 달라고 할 수 없으므로, 못 본 것을 못 봤다고 남기는 것이 기능임.
 *   부작용: 커널 PERCPU 맵을 합산해 읽음(cap_get_stats). 비싸므로 레코드마다 부르지 않고
 *     주기가 닫히기 직전과 종료 직전에만 부름. */
static void feed_coverage(struct pipeline *pipeline)
{
	/* cap_get_stats 는 하나라도 못 읽으면 출력을 0 으로 비우고 음수를 돌려줌(cap.c:487, 494-495
	 *   "0 을 '유실 없음' 으로 오해하지 않게"). 반환값을 버리면 그 경고를 그대로 어기는 것임 */
	struct cap_stats cap_stats;
	int error = cap_get_stats(pipeline->cap, &cap_stats);
	if (error) {
		pipeline->cap_stats_error_count++;
		if (pipeline->cap_stats_error_count == 1)
			fprintf(stderr, "cap_get_stats: %s - 커널 유실 카운터를 읽지 못했습니다. "
			                "이 주기의 커버리지는 직전 성공값으로 고정합니다(종료 시 총 실패 횟수 보고)\n",
			        strerror(-error));
		cap_stats = pipeline->last_cap_stats;   // 누적값을 뒤로 보내지 않음(거짓 깨끗 + 다음 주기 거짓 급증)
	} else {
		pipeline->last_cap_stats = cap_stats;
	}
	const struct sctp_stats *sctp_stats = sctp_get_stats(pipeline->sctp);

	tr_set_coverage(pipeline->tr, sctp_stats ? sctp_stats->tsn_gap_count : 0,
	                cap_stats.ringbuf_full_count, cap_stats.esp_seen_count, cap_stats.ip_frag_skipped_count);

	/* 관측자 내부 유실 + 전송계층이 버린 데이터. 뒤의 항은 "레코드까지 왔지만 메시지가 되지
	 *   못한" 것이라, 빼면 보고 헤더가 그 구간을 거짓으로 깨끗하다고 말함.
	 *   아래 여덟 개가 libsctp 의 '버렸음' 계수기임(sctp.h struct sctp_stats).
	 *     bad_header_count           : 길이가 모자라 헤더나 청크를 못 읽어 버린 패킷 (sctp.c:793,931,959)
	 *     vtag_mismatch_drop_count   : 검증 태그가 안 맞아 버린 패킷 (sctp.c:764,905)
	 *     truncated_packet_count     : 캡처가 원래 길이보다 짧게 잘린 패킷 (sctp.c:937)
	 *     partial_chunk_count        : 청크 길이가 패킷에 남은 바이트보다 커서 버린 청크 (sctp.c:797)
	 *     fragment_evicted_count     : 유효 시간이나 메모리 상한으로 버린 조각 (sctp.c:569,587,602)
	 *     alloc_failed_drop_count    : 조각 보관과 조립용 메모리 할당 실패 (sctp.c:609,680)
	 *     direction_evicted_count    : 방향 표가 꽉 차 밀어낸 레코드 (sctp.c:330)
	 *     assoc_evicted_count        : 연결 표가 꽉 차 밀어낸 레코드 (sctp.c:391)
	 *   앞의 둘을 빼면 "태그가 안 맞는 패킷을 쏟아붓는" 트래픽에서 보고가 깨끗하게 나옴.
	 *   넣지 않은 것: too_old_chunk_count(sctp.c:818) - 중복 판정 창보다 오래된 TSN 이라 넘기지 않은
	 *      청크임. 중복인지 유실인지 가릴 수 없어 유실 합에 넣으면 재전송을 유실로 셈.
	 *      그 구간의 가시성은 tsn_gap_count 가 따로 말함 */
	uint64_t sctp_lost_count = 0;
	if (sctp_stats)
		sctp_lost_count = sctp_stats->fragment_evicted_count + sctp_stats->alloc_failed_drop_count
		          + sctp_stats->partial_chunk_count + sctp_stats->truncated_packet_count
		          + sctp_stats->direction_evicted_count + sctp_stats->assoc_evicted_count
		          + sctp_stats->bad_header_count + sctp_stats->vtag_mismatch_drop_count;
	tr_set_obs_coverage(pipeline->tr, obs_internal_loss(pipeline->obs) + sctp_lost_count);
}

/* on_obs: 관측 이벤트 하나를 집계 층으로 넘김.
 *   단말 줄과 DU 줄을 여기서 따로 내지 않는 이유: 집계 층이 그 변환을 함께 함. 두 곳에서 내면
 *   주기 줄과의 순서를 여기서 다시 맞춰야 하고, 둘 중 한쪽만 고치면 조용히 어긋남 */
static void on_obs(void *user_ctx, const struct obs_event *event)
{
	struct pipeline *pipeline = user_ctx;
	tr_on_event(pipeline->tr, event);
}

/* 아래 넷은 집계 층의 콜백 서명을 출력 층 함수에 맞추는 자리임. 서명이 다른 이유는 출력 층이
 *   첫 인자로 자기 타입을 받고 버린 이유를 반환하기 때문임 - 그 반환값은 출력 층이 이미 이유별로
 *   세고 있어 여기서 다시 보지 않고, 종료 보고가 그 수를 읽음 */
static void on_period(void *user_ctx, const struct report_period *period)
{
	sink_on_period(user_ctx, period);
}
static void on_ue_event(void *user_ctx, const struct report_ue_event *event)
{
	sink_on_ue_event(user_ctx, event);
}
static void on_f1_event(void *user_ctx, const struct report_f1_event *event)
{
	sink_on_f1_event(user_ctx, event);
}
/* on_warning: 집계 층이 자기 불변식이 깨진 것을 알릴 때 부름. 줄로 내보내지 않고 stderr 로만 냄 -
 *   받는 쪽 규약에 그 줄이 없고, 이것은 우리 계산이 어긋났다는 신호라 사람이 봐야 함 */
static void on_warning(void *user_ctx, const char *code, const char *detail)
{
	(void)user_ctx;
	fprintf(stderr, "[tr] 경고: %s%s%s\n", code, detail ? " - " : "", detail ? detail : "");
}

/* count_message_by_interface: 올라온 메시지를 NIC 별로 PPID 로 셈.
 *   이유: 명령행의 역할 선언이 맞았는지 종료 때 대조하려면 '그 NIC 에서 그 프로토콜을 실제로
 *     봤는가' 를 알아야 함. cap_stats 는 탭 전체의 합이라 NIC 별로 가를 수 없음.
 *   분기에는 쓰지 않음 - F1AP 와 NGAP 를 가르는 것은 libobs 의 PPID 비교임.
 *   표에 없는 NIC 번호는 셀 칸이 없어 버림. 선언한 NIC 만 붙이므로 생기지 않음 */
static void count_message_by_interface(struct pipeline *pipeline, const struct sctp_message *sctp_message)
{
	if (!sctp_message->record)
		return;
	for (int i = 0; i < pipeline->declared_interface_count; i++) {
		struct declared_interface *declared_interface = &pipeline->declared_interfaces[i];
		if (declared_interface->interface_index != sctp_message->record->interface_index)
			continue;
		if (sctp_message->ppid == SCTP_PPID_F1AP)
			declared_interface->f1ap_message_count++;
		else if (sctp_message->ppid == SCTP_PPID_NGAP)
			declared_interface->ngap_message_count++;
		return;
	}
}

static void on_message(void *user_ctx, const struct sctp_message *sctp_message)
{
	struct pipeline *pipeline = user_ctx;
	count_message_by_interface(pipeline, sctp_message);
	obs_on_sctp(pipeline->obs, sctp_message);
}

static void on_assoc(void *user_ctx, const struct sctp_assoc_event *assoc_event)
{
	struct pipeline *pipeline = user_ctx;
	obs_on_assoc(pipeline->obs, assoc_event);
}

/* wallclock_ns: cap_record.capture_time_ns 와 같은 기준의 현재 시각.
 *   libcap 로더가 커널 TAI 를 UTC 로 바꿔 싣으므로 여기서도 CLOCK_REALTIME 을 씀(cap.c refresh_tai_offset).
 *   기준이 다르면 유휴 진행이 주기 경계를 엉뚱한 위치에 그음 */
static uint64_t wallclock_ns(void)
{
	struct timespec now;
	clock_gettime(CLOCK_REALTIME, &now);
	return (uint64_t)now.tv_sec * 1000000000ull + (uint64_t)now.tv_nsec;
}

/* advance_idle: 레코드가 없는 동안에도 시간을 진행시키고 캡처 생존을 알림.
 *
 *     레코드 없음 --> 주기가 안 닫힘 --> kpm2 줄이 안 나감 --> 엔진에 그 구간이 '없었던 것' 이 됨
 *
 *   이유: 트래픽이 없던 주기도 줄은 내보내되 카운터를 null 로 실어야 함. 그래야 읽는 쪽이 건수 0 과
 *     그 구간을 못 봤음을 가릴 수 있음. 내보내려면 먼저 주기가 닫혀야 하고, 주기는 시간이 흘러야 닫힘.
 *   워터마크를 slack 만큼 뒤로 물리는 이유: 링 버퍼에서 늦게 올라오는 레코드가 이미 닫은 주기에
 *     떨어지면 late_event_count 로 샘. TR_DEF_LATE_SLACK_MS 가 그 여유임.
 *   생존 근거: cap_poll 이 음수가 아니면 탭이 아직 붙어 있음 - 떨어지면 1초 안에 -ENODEV 임(cap.c). */
static void advance_idle(struct pipeline *pipeline, uint32_t late_slack_ms)
{
	uint64_t now_ns = wallclock_ns();
	uint64_t slack_ns = (uint64_t)late_slack_ms * 1000000ull;
	if (now_ns < slack_ns) return;   /* 시계가 1970 근처면(컨테이너 초기화 등) 진행하지 않음 */
	uint64_t watermark_ns = now_ns - slack_ns;
	if (watermark_ns <= pipeline->last_capture_time_ns) return;   /* 레코드가 이미 더 앞서 있으면 할 일 없음 */
	tr_set_capture_alive(pipeline->tr, watermark_ns);
	obs_advance(pipeline->obs, watermark_ns);
	tr_advance(pipeline->tr, watermark_ns);
}

/* on_record: libcap 이 레코드 하나를 줄 때마다 불림. 여기가 libcap 과 libsctp 의 경계임.
 *   record 와 record->sctp_packet 은 링 버퍼를 빌린 것이라 이 함수가 반환하면 무효임 - 들고 나가지 않음. */
static void on_record(void *user_ctx, const struct cap_record *record)
{
	struct pipeline *pipeline = user_ctx;
	pipeline->last_capture_time_ns = record->capture_time_ns;

	/* 커버리지는 주기가 닫히기 직전에만 갱신함. 닫힌 뒤에 갱신하면 그 주기의 손실이 다음 주기로
	 *   들어가고, 닫힌 주기는 거짓으로 깨끗해짐 */
	if (tr_period_pending_close(pipeline->tr, record->capture_time_ns))
		feed_coverage(pipeline);

	/* 레코드가 올라온 것 자체가 그 시각까지 캡처가 살아 있었다는 증거임. 여기서 알리지 않으면
	 *   트래픽이 흐르는 동안 워터마크가 멈춤 - advance_idle 은 레코드가 더 앞서 있으면 이른 반환함.
	 *   tr_advance 보다 먼저 불러야 함. tr_advance 가 이 시각까지의 주기를 닫기 때문임 */
	tr_set_capture_alive(pipeline->tr, record->capture_time_ns);

	obs_advance(pipeline->obs, record->capture_time_ns);   // 시간 먼저
	tr_advance(pipeline->tr, record->capture_time_ns);
	sctp_input(pipeline->sctp, record);                    // on_message -> obs -> on_obs -> tr_on_event -> sink
}

/* declare_interface: 이름으로 칸을 찾아 역할 플래그를 켬. 없으면 새 칸을 만듦.
 *   같은 이름을 다시 받으면 칸을 늘리지 않고 플래그만 켜는 이유: 탭은 NIC 당 한 번만 붙여야 함.
 *   반환: 칸을 확보했으면 true, MAX_INTERFACES 를 넘겼으면 false(부르는 쪽이 종료함) */
static bool declare_interface(struct declared_interface *declared_interfaces, int *declared_interface_count,
                              const char *interface_name, bool is_f1)
{
	for (int i = 0; i < *declared_interface_count; i++) {
		if (strcmp(declared_interfaces[i].interface_name, interface_name))
			continue;
		if (is_f1)
			declared_interfaces[i].is_f1_declared = true;
		else
			declared_interfaces[i].is_n2_declared = true;
		return true;
	}
	if (*declared_interface_count >= MAX_INTERFACES)
		return false;
	struct declared_interface *declared_interface = &declared_interfaces[*declared_interface_count];
	declared_interface->interface_name = interface_name;
	declared_interface->is_f1_declared = is_f1;
	declared_interface->is_n2_declared = !is_f1;
	(*declared_interface_count)++;
	return true;
}

static void usage(const char *program_name)
{
	fprintf(stderr,
	        "사용: sudo %s [옵션] f1:<interface_name> n2:<interface_name> ...\n"
	        "  f1:<interface_name>         F1-C(CU<->DU)가 흐르는 NIC. 하나 이상 필요\n"
	        "  n2:<interface_name>         N2(CU<->AMF)가 흐르는 NIC. 하나 이상 필요\n"
	        "                              같은 NIC 로 둘 다 흐르면 같은 이름을 두 역할에 적음\n"
	        "  -g <gp_ms>                  보고 주기 ms (기본 = 15분)\n"
	        "  --sock <socket_path>        탐지 엔진이 듣는 유닉스 소켓 (기본 " SINK_DEFAULT_SOCKET_PATH ")\n"
	        "  --record <file_path|->      보낸 줄을 그대로 남길 파일 (- = stdout). 형식 확인용\n"
	        "  --node <node_id>            hello 의 node_id\n"
	        "\n"
	        "종료 코드: 0 = 정상, 측정 완전 / 1 = 운영 실패(탭, 통계, 스트림) / 2 = 커버리지 불완전\n",
	        program_name);
}

int main(int argc, char **argv)
{
	const char *socket_path = NULL, *record_path = NULL, *node_id = NULL;
	uint64_t gp_ms = 0;                      // 0 = libtelemetry 기본값(15분)
	struct declared_interface declared_interfaces[MAX_INTERFACES] = { 0 };
	int declared_interface_count = 0;

	for (int i = 1; i < argc; i++) {
		const char *argument = argv[i];
		bool has_value = i + 1 < argc;
		if      (!strcmp(argument, "-g")    && has_value) {
			/* 범위 검사가 필요한 이유: libtelemetry 가 gp_ms * 1000000 을 ns 로 쓰므로(tr.c 의 gp_ns)
			 *   큰 값은 곱셈이 넘쳐 gp_ns 가 0 이 되고 첫 레코드에서 0 으로 나눔(SIGFPE). 음수는
			 *   strtoull 이 ULLONG_MAX 로 감싸 주기가 수백 년이 되어 아무 출력도 안 나옴.
			 *   상한 86400000(= 1일): 그보다 긴 보고 주기는 쓸 일이 없고 곱셈도 안전함 */
			const char *gp_text = argv[++i];
			char *parse_end;
			errno = 0;
			unsigned long long parsed_gp_ms = strtoull(gp_text, &parse_end, 10);
			if (errno || *gp_text == '\0' || *parse_end || parsed_gp_ms < 1 || parsed_gp_ms > 86400000ULL) {
				fprintf(stderr, "-g 값이 잘못됐습니다: '%s' (1~86400000 ms)\n", gp_text);
				return 2;
			}
			gp_ms = parsed_gp_ms;
		}
		else if (!strcmp(argument, "--sock")   && has_value) socket_path = argv[++i];
		else if (!strcmp(argument, "--record") && has_value) record_path = argv[++i];
		else if (!strcmp(argument, "--node")   && has_value) node_id     = argv[++i];
		else if (argument[0] == '-') { usage(argv[0]); return 2; }
		else {
			/* 옵션이 아닌 인자는 `f1:<interface_name>` 또는 `n2:<interface_name>` 임.
			 *   접두사를 요구하는 이유: 어느 NIC 가 어느 인터페이스인지를 운영자가 적게 해서,
			 *     한쪽을 빼먹거나 거꾸로 적었을 때 종료 보고가 그 사실을 말할 수 있게 함.
			 *   없는 이름은 cap_open 의 if_nametoindex 가 -ENODEV 로 거름 */
			bool is_f1 = !strncmp(argument, "f1:", 3);
			bool is_n2 = !strncmp(argument, "n2:", 3);
			if (!is_f1 && !is_n2) {
				fprintf(stderr, "인터페이스는 f1:<interface_name> 또는 n2:<interface_name> 로 적습니다: '%s'\n",
				        argument);
				return 2;
			}
			const char *interface_name = argument + 3;
			if (*interface_name == '\0') {
				fprintf(stderr, "인터페이스 이름이 비었습니다: '%s'\n", argument);
				return 2;
			}
			if (!declare_interface(declared_interfaces, &declared_interface_count, interface_name, is_f1)) {
				fprintf(stderr, "인터페이스가 너무 많습니다 (상한 %d)\n", MAX_INTERFACES);
				return 2;
			}
		}
	}
	/* 두 역할을 다 요구함. 한쪽이 없으면 그 인터페이스를 한 번도 안 봤다는 뜻인데, 출력에서는
	 *   그 지표가 0 으로 나가 '그 구간에 사건이 없었다' 와 구별되지 않음. 우리는 수동 관측자라
	 *   다시 달라고 할 수 없으므로 못 본 것을 못 봤다고 남겨야 함 */
	bool has_f1_interface = false, has_n2_interface = false;
	for (int i = 0; i < declared_interface_count; i++) {
		if (declared_interfaces[i].is_f1_declared) has_f1_interface = true;
		if (declared_interfaces[i].is_n2_declared) has_n2_interface = true;
	}
	if (!has_f1_interface || !has_n2_interface) {
		fprintf(stderr, "F1 과 N2 인터페이스를 둘 다 적어야 합니다 (f1: %s, n2: %s)\n",
		        has_f1_interface ? "있음" : "없음", has_n2_interface ? "있음" : "없음");
		usage(argv[0]);
		return 2;
	}

	/* 녹화 파일만 엶. 소켓은 출력 층이 스스로 열고 끊기면 다시 붙음 - 그 재접속 상태를 여기서
	 * 들고 있으면 같은 것을 두 곳이 기억하게 됨 */
	FILE *record_file = NULL;
	if (record_path) {
		record_file = !strcmp(record_path, "-") ? stdout : fopen(record_path, "w");
		if (!record_file) { perror(record_path); return 1; }
	}

	// ---- 파이프라인 조립 (아래에서 위로: sink, tr, obs, sctp, cap) ----
	struct pipeline pipeline = { 0 };
	/* 주기 길이와 무응답 대기를 두 층에 같은 값으로 넘김. 출력 층은 그 둘을 hello 로 광고하고 받는
	 * 쪽은 광고값으로 칸 길이를 검사하므로, 두 층이 다른 값을 쓰면 받는 쪽 판정이 조용히 틀림.
	 * 그래서 기본값으로 해소한 값을 양쪽에 넘김 - 0 을 넘기면 두 층이 서로 다른 기본값을 지어냄 */
	uint32_t period_ms = (uint32_t)(gp_ms ? gp_ms : TR_DEF_GP_MS);
	uint32_t noreply_timeout_ms = TR_DEF_NOREPLY_TIMEOUT_MS;
	struct tr_cfg tr_cfg = {
		.gp_ms              = period_ms,
		.noreply_timeout_ms = noreply_timeout_ms,
	};
	struct sink_cfg sink_cfg = {
		.socket_path        = socket_path,
		.record_file        = record_file,
		.record_max_bytes   = RECORD_MAX_BYTES,
		.period_ms          = period_ms,
		.noreply_timeout_ms = noreply_timeout_ms,
		.producer           = "PortRAN",
		.node_id            = node_id,
	};
	pipeline.sink = sink_new(&sink_cfg);
	if (!pipeline.sink) {
		fprintf(stderr, "출력 어댑터 초기화 실패 (설정이 잘못됐거나 메모리 부족)\n");
		return 1;
	}
	struct tr_sink_ops sink_ops = {
		.on_period   = on_period,
		.on_ue_event = on_ue_event,
		.on_f1_event = on_f1_event,
		.on_warning  = on_warning,
	};
	pipeline.tr = tr_new(&tr_cfg, &sink_ops, pipeline.sink);
	struct obs_cfg obs_cfg = { 0 };                 // 전부 0 = libobs 기본값
	pipeline.obs = obs_new(&obs_cfg, on_obs, &pipeline);
	pipeline.sctp = sctp_new(on_message, on_assoc, &pipeline);
	if (!pipeline.tr || !pipeline.obs || !pipeline.sctp) {
		fprintf(stderr, "파이프라인 초기화 실패 (메모리 부족)\n");
		return 1;
	}

	/* libcap 에 넘기는 표. cap_interface 의 역할 칸은 F1 과 N2 중 하나만 담으므로 한 NIC 에 둘이
	 *   다 흐르면 F1 로 넘김. libcap 은 이 값으로 분기하지 않고 인자 검증만 함(cap.c 의 role 검사) -
	 *   올라온 메시지를 F1AP 와 NGAP 로 가르는 것은 SCTP PPID 임 */
	struct cap_interface interfaces[MAX_INTERFACES];
	for (int i = 0; i < declared_interface_count; i++) {
		interfaces[i].interface_name = declared_interfaces[i].interface_name;
		interfaces[i].role = declared_interfaces[i].is_f1_declared ? CAP_ROLE_F1 : CAP_ROLE_N2;
	}

	int error = cap_open(interfaces, declared_interface_count, &pipeline.cap);
	if (error) {
		fprintf(stderr, "cap_open: %s (부착은 root 권한이 필요합니다)\n", strerror(-error));
		return 1;
	}

	/* 레코드의 인터페이스 번호와 맞출 수 있게 이름을 번호로 바꿔 둠. cap_open 이 통과한 뒤라
	 *   이름은 전부 존재하지만, 0 이 오면 그 NIC 의 계수기가 영원히 0 이 되어 선언 대조가 거짓으로
	 *   '못 봤음' 을 말하므로 여기서 멈춤 */
	for (int i = 0; i < declared_interface_count; i++) {
		declared_interfaces[i].interface_index = if_nametoindex(declared_interfaces[i].interface_name);
		if (!declared_interfaces[i].interface_index) {
			fprintf(stderr, "인터페이스 번호를 읽지 못했습니다: %s: %s\n",
			        declared_interfaces[i].interface_name, strerror(errno));
			return 1;
		}
	}
	pipeline.declared_interfaces = declared_interfaces;
	pipeline.declared_interface_count = declared_interface_count;

	struct sigaction action = { 0 };
	action.sa_handler = on_signal;
	sigaction(SIGINT, &action, NULL);
	sigaction(SIGTERM, &action, NULL);
	/* SIGPIPE 무시. --sock 의 상대인 탐지 엔진이 재시작하면 첫 쓰기에서 SIGPIPE 가 오는데
	 *   기본 동작이 즉사라, cap_detach 부터 tr_finish 까지 종료 경로가 전부 건너뛰어지고 미완
	 *   주기가 사라짐. 무시해 두면 write 가 -EPIPE 로 돌아오고 아래 ferror 검사가 그것을 잡음 */
	struct sigaction ignore_action = { 0 };
	ignore_action.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &ignore_action, NULL);

	fprintf(stderr, "[+] 탭 부착: ");
	for (int i = 0; i < declared_interface_count; i++)
		fprintf(stderr, "%s%s(%s%s%s)", i ? " " : "", declared_interfaces[i].interface_name,
		        declared_interfaces[i].is_f1_declared ? "F1" : "",
		        declared_interfaces[i].is_f1_declared && declared_interfaces[i].is_n2_declared ? "+" : "",
		        declared_interfaces[i].is_n2_declared ? "N2" : "");
	fprintf(stderr, " - Ctrl+C 로 종료\n");

	/* ── 수집 루프 ─────────────────────────────────────────────────────── */
	int exit_code = 0;             /* 1 = 운영 실패(탭, 통계, 스트림) */
	int coverage_incomplete = 0;   /* 2 = 측정은 돌았으나 커버리지 불완전. 둘을 섞지 않음([4]) */
	while (!stop_signal_count) {
		// cap_poll 은 -EINTR 와 -EAGAIN 을 스스로 0 이상으로 바꿔 돌려줌(cap.c:417-419) -> 음수면 실제 오류임
		int delivered_count = cap_poll(pipeline.cap, 200, on_record, &pipeline);   // 200 ms 마다 돌아와 stop_signal_count 를 봄
		if (delivered_count < 0) {
			fprintf(stderr, "cap_poll: %s%s\n", strerror(-delivered_count),
			        delivered_count == -ENODEV ? " (붙여 둔 인터페이스가 사라짐)" : "");
			exit_code = 1;   // 감시 프로세스가 재시작하거나 경보할 수 있게 종료코드로 알림
			break;   // 생존 워터마크를 올리지 않고 나감 - 이 뒤 주기는 '확인되지 않음' 임
		}
		advance_idle(&pipeline, TR_DEF_LATE_SLACK_MS);   // 트래픽이 없어도 주기는 닫혀 나가야 함
	}

	/* 종료 순서. 바꾸면 "넘긴 수 < captured_count" 가 되어 유실로 오해됨.
	 *
	 *     cap_detach --> 남은 것 비우기 --> feed_coverage --> tr_finish --> 통계 출력 --> free
	 *     새 유입 중단      링 버퍼          마지막 주기분     미완 주기 닫음
	 */
	cap_detach(pipeline.cap);
	/* 비우기에서 음수 반환과 '다 비웠다' 를 구별해야 함. 종료 중 NIC 가 사라지면(-ENODEV) 링에
	 *   남은 레코드를 버린 채 tr_finish 가 마지막 주기를 완전한 것처럼 닫고 exit 0 으로 나감
	 *   (= 신호 없는 드롭). 오류를 따로 말하고 커버리지 불완전으로 표시함 */
	while (stop_signal_count < 2) {
		int delivered_count = cap_poll(pipeline.cap, 0, on_record, &pipeline);
		if (delivered_count > 0) continue;
		if (delivered_count < 0) {
			fprintf(stderr, "[cap] 종료 중 남은 레코드 비우기 실패: %s "
			                "(링 버퍼에 남은 레코드를 못 꺼냈습니다 - 마지막 주기가 불완전합니다)\n",
			        strerror(-delivered_count));
			coverage_incomplete = 1;
		}
		break;
	}

	feed_coverage(&pipeline);                                 // 마지막 미완 주기분
	tr_finish(pipeline.tr, pipeline.last_capture_time_ns);    // 미완 주기를 닫아 내보냄

	struct cap_stats cap_stats;
	error = cap_get_stats(pipeline.cap, &cap_stats);
	if (error) {
		// 0 을 찍으면 "아무것도 못 잡은 실행" 과 구분이 안 됨 -> 못 읽었다고 말함
		fprintf(stderr, "[cap] 통계를 읽지 못함: %s\n", strerror(-error));
		exit_code = 1;
	} else {
		fprintf(stderr, "[cap] captured_count=%llu ringbuf_full_count=%llu (그중 slot_busy_count=%llu) "
		                "truncated_count=%llu ip_frag_skipped_count=%llu esp_seen_count=%llu\n",
		        (unsigned long long)cap_stats.captured_count, (unsigned long long)cap_stats.ringbuf_full_count,
		        (unsigned long long)cap_stats.slot_busy_count,
		        (unsigned long long)cap_stats.truncated_count, (unsigned long long)cap_stats.ip_frag_skipped_count,
		        (unsigned long long)cap_stats.esp_seen_count);
		// 작업 공간 칸 사용 분포. 0 이 아닌 가장 높은 번호 = 실측 재진입 깊이 = CAP_SLOT_MAX 적정성 근거
		fprintf(stderr, "[cap] slot_used_count=");
		for (int slot_index = 0; slot_index < CAP_SLOT_MAX; slot_index++)
			fprintf(stderr, "%s%llu", slot_index ? "," : "", (unsigned long long)cap_stats.slot_used_count[slot_index]);
		fputc('\n', stderr);
	}

	/* 명령행의 역할 선언을 실제로 본 프로토콜과 대조함.
	 *   왜 필요한가: 선언만 받고 대조하지 않으면 틀리게 적어도 출력이 같아 알 수 없음. 특히 한쪽
	 *     NIC 를 빼먹으면 그 지표가 0 으로 나가는데, 그 0 은 '그 구간에 사건이 없었다' 와 같은
	 *     모양임. 못 본 것을 못 봤다고 남기는 것이 관측자의 기능임.
	 *   선언하지 않은 쪽이 올라온 경우는 커버리지 불완전으로 올리지 않음 - 분기는 PPID 가 하므로
	 *     지표는 맞게 나오고, 틀린 것은 운영자가 적은 선언뿐임 */
	fprintf(stderr, "[cap] 인터페이스별 메시지 수(SCTP PPID 로 셈)\n");
	for (int i = 0; i < pipeline.declared_interface_count; i++) {
		const struct declared_interface *declared_interface = &pipeline.declared_interfaces[i];
		fprintf(stderr, "[cap]   %s 선언=%s%s%s F1AP=%llu NGAP=%llu\n",
		        declared_interface->interface_name,
		        declared_interface->is_f1_declared ? "F1" : "",
		        declared_interface->is_f1_declared && declared_interface->is_n2_declared ? "+" : "",
		        declared_interface->is_n2_declared ? "N2" : "",
		        (unsigned long long)declared_interface->f1ap_message_count,
		        (unsigned long long)declared_interface->ngap_message_count);
		if (declared_interface->is_f1_declared && !declared_interface->f1ap_message_count) {
			fprintf(stderr, "[cap]   %s: F1 로 선언했으나 F1AP(PPID %d)를 한 건도 못 봤습니다\n",
			        declared_interface->interface_name, SCTP_PPID_F1AP);
			coverage_incomplete = 1;
		}
		if (declared_interface->is_n2_declared && !declared_interface->ngap_message_count) {
			fprintf(stderr, "[cap]   %s: N2 로 선언했으나 NGAP(PPID %d)를 한 건도 못 봤습니다\n",
			        declared_interface->interface_name, SCTP_PPID_NGAP);
			coverage_incomplete = 1;
		}
		if (!declared_interface->is_f1_declared && declared_interface->f1ap_message_count)
			fprintf(stderr, "[cap]   %s: F1 로 선언하지 않았는데 F1AP 가 올라왔습니다 (선언을 고쳐야 함)\n",
			        declared_interface->interface_name);
		if (!declared_interface->is_n2_declared && declared_interface->ngap_message_count)
			fprintf(stderr, "[cap]   %s: N2 로 선언하지 않았는데 NGAP 가 올라왔습니다 (선언을 고쳐야 함)\n",
			        declared_interface->interface_name);
	}

	/* 두 탭이 같은 패킷을 같이 봤는지 알 수 있는 유일한 신호임. libsctp 가 연결 안에서 TSN 으로
	 *   걸러 지표가 두 배가 되지는 않지만, 그 수를 읽는 곳이 없으면 겹친 사실을 아무도 모름.
	 *   재전송으로도 올라가므로 0 이 아닌 것 자체가 결함은 아님 - 그래서 종료 코드를 바꾸지 않음 */
	const struct sctp_stats *sctp_stats = sctp_get_stats(pipeline.sctp);
	if (sctp_stats && sctp_stats->duplicate_chunk_count)
		fprintf(stderr, "[sctp] 이미 본 TSN 으로 버린 청크 %llu 개 (재전송이거나 두 탭이 같은 패킷을 본 것)\n",
		        (unsigned long long)sctp_stats->duplicate_chunk_count);

	/* 관측기 계측을 전부 찍음. 계수기를 올려도 읽는 쪽이 없으면 절반만 한 것임 - 소비자가
	 *   obs_internal_loss 하나뿐이던 동안 direction_unknown_count 등은 어떤 출력에도 닿지 않는
	 *   쓰기 전용 계수기였음.
	 *   obs_internal_loss(보고 헤더의 obs_lost_count) 공식은 건드리지 않음. 그건 와이어에 나가는
	 *   수라 뜻을 바꾸면 표 II 의 의미가 조용히 달라짐. 여기서는 진단 채널로만 내보내고,
	 *   '맹점' 성격인 것만 아래에서 커버리지 불완전으로 표시함 */
	const struct obs_stats *obs_stats = obs_get_stats(pipeline.obs);
	if (obs_stats) {
		fprintf(stderr, "[obs] corr_unique_count=%llu corr_ambiguous_count=%llu corr_unmatched_f1_count=%llu "
		                "corr_unmatched_n2_count=%llu corr_expired_count=%llu "
		                "ue_evicted_count=%llu ue_replaced_count=%llu du_id_reuse_count=%llu "
		                "f1_reset_removed_count=%llu ng_reset_removed_count=%llu f1_setup_ambiguous_count=%llu\n",
		        (unsigned long long)obs_stats->corr_unique_count, (unsigned long long)obs_stats->corr_ambiguous_count,
		        (unsigned long long)obs_stats->corr_unmatched_f1_count, (unsigned long long)obs_stats->corr_unmatched_n2_count,
		        (unsigned long long)obs_stats->corr_expired_count, (unsigned long long)obs_stats->ue_evicted_count,
		        (unsigned long long)obs_stats->ue_replaced_count, (unsigned long long)obs_stats->du_id_reuse_count,
		        (unsigned long long)obs_stats->f1_reset_removed_count, (unsigned long long)obs_stats->ng_reset_removed_count,
		        (unsigned long long)obs_stats->f1_setup_ambiguous_count);
		fprintf(stderr, "[obs] f1_grace_expired_count=%llu n2_grace_expired_count=%llu corr_queue_overflow_count=%llu dcch_gate_closed_on_cap_count=%llu "
		                "dtls_seen_count=%llu direction_unknown_count=%llu direction_conflict_count=%llu assoc_table_full_count=%llu "
		                "amf_key_table_full_count=%llu rrc_state_report_no_ie_count=%llu\n",
		        (unsigned long long)obs_stats->f1_grace_expired_count, (unsigned long long)obs_stats->n2_grace_expired_count,
		        (unsigned long long)obs_stats->corr_queue_overflow_count,
		        (unsigned long long)obs_stats->dcch_gate_closed_on_cap_count, (unsigned long long)obs_stats->dtls_seen_count,
		        (unsigned long long)obs_stats->direction_unknown_count, (unsigned long long)obs_stats->direction_conflict_count,
		        (unsigned long long)obs_stats->assoc_table_full_count,
		        (unsigned long long)obs_stats->amf_key_table_full_count,
		        (unsigned long long)obs_stats->rrc_state_report_no_ie_count);
		fprintf(stderr, "[obs] ap_body_unknown_count=%llu ngap_unknown_ie_count=%llu ngap_rejected_ie_count=%llu "
		                "ngap_duplicate_ie_count=%llu ngap_type_mismatch_ie_count=%llu "
		                "ue_ctx_setup_failure_cause_dropped_count=%llu\n",
		        (unsigned long long)obs_stats->ap_body_unknown_count, (unsigned long long)obs_stats->ngap_unknown_ie_count,
		        (unsigned long long)obs_stats->ngap_rejected_ie_count, (unsigned long long)obs_stats->ngap_duplicate_ie_count,
		        (unsigned long long)obs_stats->ngap_type_mismatch_ie_count,
		        (unsigned long long)obs_stats->ue_ctx_setup_failure_cause_dropped_count);
		/* 보존 검산 세 수 + 모르는 PPID.
		 *     sctp_message_count  ==  event_emitted_count + handled_no_event_count
		 *   양변이라 값 자체가 결함 신호는 아니지만, 안 맞으면 어느 계층이 조용히 버린 것임.
		 *   unknown_ppid_count 는 성격이 다름 - 그 SCTP 연결에 우리가 모르는 것이 흐른다는 뜻임 */
		fprintf(stderr, "[obs] sctp_message_count=%llu event_emitted_count=%llu handled_no_event_count=%llu "
		                "unknown_ppid_count=%llu\n",
		        (unsigned long long)obs_stats->sctp_message_count, (unsigned long long)obs_stats->event_emitted_count,
		        (unsigned long long)obs_stats->handled_no_event_count, (unsigned long long)obs_stats->unknown_ppid_count);
		fprintf(stderr, "[obs] nas_malformed_count=%llu nas_truncated_count=%llu nas_epd_mismatch_count=%llu "
		                "nas_reserved_sht_count=%llu nas_unknown_msg_type_count=%llu nas_missing_mandatory_ie_count=%llu "
		                "nas_rejected_ie_count=%llu\n",
		        (unsigned long long)obs_stats->nas_malformed_count,
		        (unsigned long long)obs_stats->nas_truncated_count,
		        (unsigned long long)obs_stats->nas_epd_mismatch_count,
		        (unsigned long long)obs_stats->nas_reserved_sht_count,
		        (unsigned long long)obs_stats->nas_unknown_msg_type_count,
		        (unsigned long long)obs_stats->nas_missing_mandatory_ie_count,
		        (unsigned long long)obs_stats->nas_rejected_ie_count);
		fprintf(stderr, "[obs] nas_direction_mismatch_count=%llu nas_direction_unjudged_count=%llu "
		                "nas_smc_learn_skipped_count=%llu nas_sec_header_direction_mismatch_count=%llu "
		                "nas_sec_header_direction_unjudged_count=%llu nas_pdu_absent_count=%llu "
		                "nas_ie_scan_aborted_count=%llu\n",
		        (unsigned long long)obs_stats->nas_direction_mismatch_count,
		        (unsigned long long)obs_stats->nas_direction_unjudged_count,
		        (unsigned long long)obs_stats->nas_smc_learn_skipped_count,
		        (unsigned long long)obs_stats->nas_sec_header_direction_mismatch_count,
		        (unsigned long long)obs_stats->nas_sec_header_direction_unjudged_count,
		        (unsigned long long)obs_stats->nas_pdu_absent_count,
		        (unsigned long long)obs_stats->nas_ie_scan_aborted_count);
		/* 아래는 "봤지만 해석하지 못했다" = 맹점임. 0 이 아니면 '깨끗한 측정' 이라고 말할 수 없음 */
		if (obs_stats->assoc_table_full_count)
			fprintf(stderr, "[coverage] 경고: SCTP assoc 표가 꽉 차 %llu 개 연결의 DU 매핑을 못 만들었습니다 "
			                "(그 연결의 UE 는 임시 DU 키로 떨어집니다)\n", (unsigned long long)obs_stats->assoc_table_full_count);
		if (obs_stats->rrc_state_report_no_ie_count)
			fprintf(stderr, "[coverage] 경고: RRC INACTIVE TRANSITION REPORT %llu 건에서 RRCState IE(92)를 못 읽었습니다 "
			                "(ASN.1 상 mandatory - 디코더 판본 차이나 기형 입력 신호. 상태를 지어내지 않았습니다)\n",
			        (unsigned long long)obs_stats->rrc_state_report_no_ie_count);
		if (obs_stats->dtls_seen_count)
			fprintf(stderr, "[coverage] 경고: DTLS-over-SCTP %llu 건 - 그 구간의 제어평면은 통째로 불가시입니다\n",
			        (unsigned long long)obs_stats->dtls_seen_count);
		/* NAS 는 두 갈래로 나눠 적음. 합치면 지표에서 정반대인 두 뜻이 같은 모양이 됨.
		 *
		 *     우리가 못 읽었나  -->  nas_blind_count     우리 관측의 구멍
		 *     상대가 그렇게 보냈나 -> nas_offspec_count   탐지 신호
		 *
		 *   잘림과 필수 IE 누락은 상대가 정한 길이임 - 잘린 SCTP 청크는 libsctp 가 부분 조각에서
		 *   멈춰 디코더에 닿지 않으므로 우리 캡처 손실로는 여기 올 수 없음.
		 *   알고리즘 미학습(smc_learn_skipped)은 행동이고 이유가 아니라 어느 합에도 넣지 않음 -
		 *   이유는 방향 어긋남과 방향 미상 두 칸이 이미 세고 있어 합치면 두 번 셈 */
		uint64_t nas_blind_count = obs_stats->nas_unknown_msg_type_count + obs_stats->nas_direction_unjudged_count
		                         + obs_stats->nas_sec_header_direction_unjudged_count;
		if (nas_blind_count)
			fprintf(stderr, "[coverage] 경고: NAS %llu 건을 해석하지 못했습니다 "
			                "(모르는 타입 %llu, 메시지 방향 미상 %llu, 보안 헤더 방향 미상 %llu)\n",
			        (unsigned long long)nas_blind_count,
			        (unsigned long long)obs_stats->nas_unknown_msg_type_count,
			        (unsigned long long)obs_stats->nas_direction_unjudged_count,
			        (unsigned long long)obs_stats->nas_sec_header_direction_unjudged_count);
		uint64_t nas_offspec_count = obs_stats->nas_truncated_count + obs_stats->nas_epd_mismatch_count
		                           + obs_stats->nas_reserved_sht_count + obs_stats->nas_missing_mandatory_ie_count
		                           + obs_stats->nas_rejected_ie_count + obs_stats->nas_direction_mismatch_count
		                           + obs_stats->nas_sec_header_direction_mismatch_count
		                           + obs_stats->nas_pdu_absent_count + obs_stats->nas_ie_scan_aborted_count;
		if (nas_offspec_count)
			fprintf(stderr, "[nas] 규격 밖 NAS %llu 건 "
			                "(잘림 %llu, EPD 불일치 %llu, 예약 SHT %llu, 필수 IE 누락 %llu, IE 값 범위 밖 %llu, "
			                "메시지 방향 위반 %llu, 보안 헤더 방향 위반 %llu, 필수 NAS-PDU 부재 %llu, IE 길이 과장 %llu) "
			                "- 담지 않았습니다. 커버리지 문제가 아니라 상대가 보낸 것입니다\n",
			        (unsigned long long)nas_offspec_count,
			        (unsigned long long)obs_stats->nas_truncated_count,
			        (unsigned long long)obs_stats->nas_epd_mismatch_count,
			        (unsigned long long)obs_stats->nas_reserved_sht_count,
			        (unsigned long long)obs_stats->nas_missing_mandatory_ie_count,
			        (unsigned long long)obs_stats->nas_rejected_ie_count,
			        (unsigned long long)obs_stats->nas_direction_mismatch_count,
			        (unsigned long long)obs_stats->nas_sec_header_direction_mismatch_count,
			        (unsigned long long)obs_stats->nas_pdu_absent_count,
			        (unsigned long long)obs_stats->nas_ie_scan_aborted_count);
		if (obs_stats->nas_smc_learn_skipped_count)
			fprintf(stderr, "[nas] SMC 모양 NAS %llu 건에서 암호 알고리즘을 학습하지 않았습니다 "
			                "(하행 SHT 3 이 아니었음 - 이유는 위 두 방향 칸)\n",
			        (unsigned long long)obs_stats->nas_smc_learn_skipped_count);
		/* 아래 둘은 버린 것이 아니라 담았지만 확신이 덜한 것이라 위 합계에 넣지 않음.
		 *   넣으면 그 줄의 "담지 않았습니다" 가 거짓이 됨 */
		if (obs_stats->nas_unknown_tlve_iei_count)
			fprintf(stderr, "[nas] 그 메시지 표에 없는 0x70~0x7F IEI %llu 개를 TLV-E(TS 24.501 §9.11.1 타입 4)로 "
			                "건너뛰었습니다 - 길이는 맞았으니 뒤따르는 IE 는 온전합니다\n",
			        (unsigned long long)obs_stats->nas_unknown_tlve_iei_count);
		if (obs_stats->nas_inner_not_plain_count)
			fprintf(stderr, "[nas] 보호된 NAS %llu 건의 안쪽 보안 헤더 타입이 0 이 아닙니다 "
			                "(TS 24.501 §8.2.28.1 은 안쪽을 평문으로 정함). 그 판의 메시지 타입은 "
			                "실제 타입일 수도 MAC 첫 옥텟일 수도 있어 바이트로는 못 가립니다\n",
			        (unsigned long long)obs_stats->nas_inner_not_plain_count);
		/* 관문에 넣는 기준은 "봤는데 해석하지 못했다" 임. AP 본문 미상과 암호로 닫힌 DCCH 관문도
		 *   같은 성격이므로 같이 넣음 - NAS 쪽만 넣으면 형제 비대칭임 */
		if (obs_stats->assoc_table_full_count || obs_stats->rrc_state_report_no_ie_count
		    || obs_stats->dtls_seen_count || obs_stats->ap_body_unknown_count
		    || obs_stats->dcch_gate_closed_on_cap_count || nas_blind_count)
			coverage_incomplete = 1;
	}

	/* 커버리지가 불완전했으면 반드시 말함 - 조용히 넘기면 '깨끗한 측정' 과 구분이 안 됨 */
	if (pipeline.cap_stats_error_count) {
		fprintf(stderr, "[coverage] 경고: 커널 유실 카운터 읽기가 %llu 회 실패 -> 그만큼의 주기 커버리지가 불완전합니다\n",
		        (unsigned long long)pipeline.cap_stats_error_count);
		coverage_incomplete = 1;
	}
	/* 내보내지 못한 줄과 주기를 이유별로 보고함. 출처가 둘인 이유: 집계 층은 자기가 안 넘긴 것을
	 * 세고, 출력 층은 넘겨받은 뒤 버린 것을 셈. 한쪽만 보면 어느 단계에서 사라졌는지 알 수 없음.
	 * 수동 관측자는 다시 달라고 할 수 없으므로, 이 수들이 그 구간의 지표가 하한이라는 유일한 신호임 */
	const struct tr_stats *tr_stats = tr_get_stats(pipeline.tr);
	if (tr_stats) {
		static const char *const skip_reason[TR_UE_EVENT_SKIP__COUNT] = {
			"셀(NR-CGI) 미상", "단말 키(DU UE F1AP ID) 미상", "방향(UL/DL) 미상", "관측자가 합성한 해제 완료",
			"전달되지 않은 NAS", "NAS 해석 실패 또는 보안 헤더 방향 위반",
			"아는 5GMM 메시지 번호가 아님", "5GMM 이 아닌 판별자",
		};
		for (int reason = 0; reason < TR_UE_EVENT_SKIP__COUNT; reason++) {
			if (!tr_stats->ue_event_skipped_count[reason]) continue;
			fprintf(stderr, "[tr] 단말 줄 %llu 개를 내보내지 않음: %s\n",
			        (unsigned long long)tr_stats->ue_event_skipped_count[reason], skip_reason[reason]);
			coverage_incomplete = 1;
		}
		if (tr_stats->unreported_period_count)
			fprintf(stderr, "[tr] 길이가 온전하지 않아 내보내지 않은 주기 %llu 개 "
			                "(기동 또는 종료 시각이 주기 경계가 아님)\n",
			        (unsigned long long)tr_stats->unreported_period_count);
		if (tr_stats->ue_event_direction_disagree_count) {
			fprintf(stderr, "[tr] 경고: 관측 층이 알려 준 방향과 규격상 방향이 다른 메시지 %llu 건 "
			                "(줄은 규격 쪽 방향으로 냈습니다 - 관측 층 결함 신호입니다)\n",
			        (unsigned long long)tr_stats->ue_event_direction_disagree_count);
			coverage_incomplete = 1;
		}
		if (tr_stats->cell_number_collision_count) {
			fprintf(stderr, "[tr] 경고: PLMN 이 다른 셀 %llu 건이 같은 NR Cell Identity 를 써 "
			                "셀 번호가 겹쳐 나갔습니다 (그 구간의 셀별 줄을 믿을 수 없습니다)\n",
			        (unsigned long long)tr_stats->cell_number_collision_count);
			coverage_incomplete = 1;
		}
		if (tr_stats->lost_evicted_count) {
			fprintf(stderr, "[tr] 표가 꽉 차 밀어낸 단말 레코드 %llu 개 "
			                "(그 단말의 뒤 이벤트는 수립 이력 없이 처리됐습니다)\n",
			        (unsigned long long)tr_stats->lost_evicted_count);
			coverage_incomplete = 1;
		}
		if (tr_stats->reset_unresolved_count) {
			fprintf(stderr, "[tr] RESET 이 가리켰지만 우리 색인으로 닫지 못한 단말 %llu 개 "
			                "(연결 수 지표가 그만큼 과대일 수 있습니다)\n",
			        (unsigned long long)tr_stats->reset_unresolved_count);
			coverage_incomplete = 1;
		}
		if (tr_stats->inactive_observed_count) {
			fprintf(stderr, "[tr] 이 망이 RRC_INACTIVE 를 쓴다고 확인된 %llu 건 "
			                "(연결 수 지표는 하한입니다 - INACTIVE 에서 돌아오는 것을 볼 수 없습니다)\n",
			        (unsigned long long)tr_stats->inactive_observed_count);
			coverage_incomplete = 1;
		}
		if (tr_stats->release_basis_observed_count || tr_stats->release_basis_assumed_count)
			fprintf(stderr, "[tr] 완전 해제 판정 근거: 평문 관측 %llu, 구조 추론 %llu\n",
			        (unsigned long long)tr_stats->release_basis_observed_count,
			        (unsigned long long)tr_stats->release_basis_assumed_count);
		if (tr_stats->nas_msg_type_inferred_count)
			fprintf(stderr, "[tr] NAS 메시지 종류를 와이어에서 읽지 못하고 보안 헤더와 방향으로 추론한 줄 %llu 개 "
			                "(줄에는 추론임을 적을 칸이 없습니다)\n",
			        (unsigned long long)tr_stats->nas_msg_type_inferred_count);
		if (tr_stats->rrc_malformed_count || tr_stats->ap_decode_fail_count) {
			fprintf(stderr, "[tr] 해석 실패로 어느 줄에도 못 들어간 수: RRC %llu, F1AP/NGAP %llu\n",
			        (unsigned long long)tr_stats->rrc_malformed_count,
			        (unsigned long long)tr_stats->ap_decode_fail_count);
			coverage_incomplete = 1;
		}
		if (tr_stats->f1_event_cells_unknown_count || tr_stats->f1_event_du_ue_id_missing_count)
			fprintf(stderr, "[tr] DU 줄: 셀 번호를 못 준 셀 %llu 건(모든 셀로 내림), "
			                "DU 번호가 없어 단말 목록에서 뺀 항목 %llu 건\n",
			        (unsigned long long)tr_stats->f1_event_cells_unknown_count,
			        (unsigned long long)tr_stats->f1_event_du_ue_id_missing_count);
		static const char *const excl_reason[TR_EXCLUDED__COUNT] = {
			"마감 안에 같은 단말이 다시 요청", "AMF 과부하 구간",
			"결판은 났지만 어느 셀의 시도인지 모름",
			"폴백으로 열린 수립의 Complete", "이미 결판난 시도에 다시 온 Complete",
		};
		for (int reason = 0; reason < TR_EXCLUDED__COUNT; reason++) {
			if (!tr_stats->excluded_count[reason]) continue;
			fprintf(stderr, "[tr] 카운팅 규칙이 제외한 사건 %llu 건: %s\n",
			        (unsigned long long)tr_stats->excluded_count[reason], excl_reason[reason]);
		}
		/* 주기 줄에 값으로 못 싣는 지표의 센 수. 재수립과 재개는 측정 가능성이 형제 칸마다 달라
		 * 값 없이 내보내므로, 센 수가 여기에만 남음 */
		for (int metric = 0; metric < TR_METRIC__COUNT; metric++) {
			if (!tr_stats->value_count[metric] && !tr_stats->unknown_count[metric]
			    && !tr_stats->unknown_nocause_count[metric]) continue;
			fprintf(stderr, "[tr] %-34s 본값 %llu, 근거 없음 %llu, 원인 미상 %llu\n",
			        tr_metric_name(metric),
			        (unsigned long long)tr_stats->value_count[metric],
			        (unsigned long long)tr_stats->unknown_count[metric],
			        (unsigned long long)tr_stats->unknown_nocause_count[metric]);
		}
	}

	const struct sink_stats *sink_stats = sink_get_stats(pipeline.sink);
	if (sink_stats) {
		fprintf(stderr, "[sink] 보낸 줄 %llu (hello %llu), 재접속 %llu, inferred 합 %llu\n",
		        (unsigned long long)sink_stats->line_count, (unsigned long long)sink_stats->hello_count,
		        (unsigned long long)sink_stats->reconnect_count, (unsigned long long)sink_stats->inferred_count);
		if (sink_stats->invalid_drop_count || sink_stats->disconnected_drop_count
		    || sink_stats->too_long_drop_count || sink_stats->write_error_count) {
			fprintf(stderr, "[sink] 버린 줄: 형식 %llu, 미접속 %llu, 길이 초과 %llu, 쓰기 실패 %llu\n",
			        (unsigned long long)sink_stats->invalid_drop_count,
			        (unsigned long long)sink_stats->disconnected_drop_count,
			        (unsigned long long)sink_stats->too_long_drop_count,
			        (unsigned long long)sink_stats->write_error_count);
			coverage_incomplete = 1;
		}
		if (sink_stats->write_error_count) exit_code = 1;
		/* 보냈지만 받는 쪽이 경고를 낼 모양이었던 줄. 우리 계산이 어긋난 흔적임 */
		if (sink_stats->spec_warning_count) {
			fprintf(stderr, "[sink] 경고: 규약과 어긋난 모양으로 나간 줄 %llu 개 "
			                "(원인 합이 total 과 다르거나 칸 길이가 광고값과 다름)\n",
			        (unsigned long long)sink_stats->spec_warning_count);
			coverage_incomplete = 1;
		}
		if (record_file)
			fprintf(stderr, "[sink] 녹화 %llu 바이트 (상한 %llu)\n",
			        (unsigned long long)sink_stats->record_bytes,
			        (unsigned long long)RECORD_MAX_BYTES);
		if (sink_stats->is_record_stopped)
			fprintf(stderr, "[sink] 녹화를 멈췄습니다 (상한 초과 또는 파일 쓰기 실패). 전송은 계속했습니다\n");
	}

	/* 쓰기 오류 검사. 탐지 엔진이 재시작해 소켓이 닫히면 모든 write 가 EPIPE 로 실패하는데,
	 *   fprintf 반환을 버리면 스트림 전체가 조용히 사라진 채 exit 0 으로 나감(= 전량 유실 +
	 *   성공 종료, 가장 나쁜 등급). fclose 반환으로는 못 잡음 - 그쪽은 0 을 돌려줌.
	 *   stdio 가 래치하는 ferror 가 유일한 신호임 */
	if (record_file && ferror(record_file)) {
		fprintf(stderr, "[io] 오류: 녹화 파일 쓰기가 실패했습니다 (디스크 가득 등). 전송은 별개입니다\n");
		exit_code = 1;
	}

	cap_close(pipeline.cap);
	sctp_free(pipeline.sctp);
	obs_free(pipeline.obs);
	tr_free(pipeline.tr);
	sink_free(pipeline.sink);
	/* fclose 반환도 검사함. 버퍼에 남은 내용을 내보내다 실패할 수 있고, 그건 위 ferror 뒤에 생길 수도 있음 */
	if (record_file && record_file != stdout && fclose(record_file) != 0) {
		fprintf(stderr, "[io] 오류: 녹화 파일 닫기 실패: %s\n", strerror(errno));
		exit_code = 1;
	}
	if (exit_code) return exit_code;                 /* 1 = 운영 실패 */
	return coverage_incomplete ? 2 : 0;              /* 2 = 커버리지 불완전. 둘을 섞지 않음([4]) */
}
