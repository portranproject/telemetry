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
 *                                  +-> sink_kpm2_on_obs_event       표 I ue_evt 줄
 *                                  +-> tr_on_event -> libtelemetry  표 I/II 집계
 *                                                        |
 *                                                        v
 *                                                     libsink       JSONL 또는 kpm2
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
 *     sudo ./build/portran [옵션] <interface_name> ...
 *       NIC 하나에 이름 하나씩, 최대 MAX_INTERFACES 개. 같은 NIC 를 두 번 적으면 cap_open 이
 *       -EEXIST 로 거부함 - 패킷이 두 번 잡혀 지표가 두 배가 되기 때문임.
 *       F1 과 N2 를 가르는 것은 SCTP PPID 임(62 F1AP, 60 NGAP, 68/66 은 그 둘의 DTLS).
 *       명령행이 아니므로 둘이 같은 NIC 를 쓰면 그 NIC 를 한 번만 적으면 됨.
 *
 *       --ii <file_path>                표 II 출력 (기본 stdout)              [sink_jsonl]
 *       --i  <file_path>                표 I  출력 (기본 stderr)              [sink_jsonl]
 *       -g <gp_ms>                      보고 주기 ms (기본값 단일출처는 tr.h)
 *       --kpm2 <file_path|->            kpm2 스트림을 파일 또는 stdout 으로   [탐지 엔진]
 *       --kpm2-sock <kpm2_socket_path>  kpm2 스트림을 유닉스 스트림 소켓으로  [탐지 엔진]
 *       --session <session>             kpm2 session (기본 "portran")
 *       --node <node_id>                kpm2 hello.node_id
 *       --ue-evt                        kpm2 에서 표 I ue_evt 줄도 냄(2단계 룰)
 *
 *     Ctrl+C 한 번이면 부착을 풀고 링 버퍼에 남은 레코드를 마저 처리한 뒤 마지막 미완 주기를
 *     닫음. 두 번이면 남은 처리를 건너뜀.
 */
#include <errno.h>              // errno: 소켓 연결 실패 사유
#include <signal.h>             // sigaction: Ctrl+C(SIGINT) 및 SIGTERM
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>             // calloc, free, strtoull
#include <string.h>             // strcmp, strlen, memcpy, strerror
#include <sys/socket.h>         // socket, connect: --kpm2-sock
#include <sys/un.h>             // struct sockaddr_un
#include <time.h>               // clock_gettime: 레코드가 없는 동안에도 시간을 진행시킴
#include <unistd.h>             // close

#include <libcap/cap.h>
#include <libsctp/sctp.h>
#include <libobs/obs.h>
#include <libtelemetry/tr.h>
#include <libsink/sink.h>
#include <libsink/sink_kpm2.h>

#define MAX_INTERFACES 8        // 인터페이스 수 상한. CU 한 대의 F1/N2 NIC 는 보통 1~2 개임

/* 파이프라인 한 벌. 모든 콜백의 user_ctx 가 이 구조체를 가리킴 */
struct pipeline {
	struct cap *cap;                // 캡처(커널 탭). 커버리지 통계를 여기서 읽음
	struct sctp_ctx *sctp;
	struct obs *obs;
	struct tr *tr;
	struct sink *sink;
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

/* on_obs: 관측 이벤트 하나를 탐지 엔진용 ue_evt 줄과 지표 집계 양쪽으로 넘김.
 *   sink_kpm2_on_obs_event 는 kpm2 sink 가 아니면 스스로 아무 일도 안 하므로 조건 없이 부름 */
static void on_obs(void *user_ctx, const struct obs_event *event)
{
	struct pipeline *pipeline = user_ctx;
	sink_kpm2_on_obs_event(pipeline->sink, event);
	tr_on_event(pipeline->tr, event);
}

static void on_message(void *user_ctx, const struct sctp_message *sctp_message)
{
	struct pipeline *pipeline = user_ctx;
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
 *     떨어지면 late_event_count 로 샘. tr_cfg.late_slack_ms 가 그 여유임.
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

/* open_unix_stream: 탐지 엔진이 듣고 있는 유닉스 스트림 소켓에 붙어 FILE* 로 감쌈.
 *   이유: kpm2 sink 는 FILE* 에 줄 단위로 씀. 소켓을 fdopen 하면 같은 sink 를 그대로 쓸 수 있음.
 *   반환: 실패하면 NULL(사유는 stderr). 성공하면 호출자가 fclose 로 닫음 */
static FILE *open_unix_stream(const char *kpm2_socket_path)
{
	struct sockaddr_un address;
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	if (strlen(kpm2_socket_path) >= sizeof(address.sun_path)) {
		fprintf(stderr, "--kpm2-sock 경로가 너무 깁니다 (상한 %zu): %s\n", sizeof(address.sun_path) - 1, kpm2_socket_path);
		return NULL;
	}
	memcpy(address.sun_path, kpm2_socket_path, strlen(kpm2_socket_path));

	int socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (socket_fd < 0) {
		fprintf(stderr, "socket(AF_UNIX): %s\n", strerror(errno));
		return NULL;
	}
	if (connect(socket_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
		fprintf(stderr, "connect(%s): %s - 탐지 엔진이 먼저 듣고 있어야 합니다\n", kpm2_socket_path, strerror(errno));
		close(socket_fd);
		return NULL;
	}
	FILE *kpm2_stream = fdopen(socket_fd, "w");
	if (!kpm2_stream) {
		fprintf(stderr, "fdopen: %s\n", strerror(errno));
		close(socket_fd);
		return NULL;
	}
	return kpm2_stream;
}

static void usage(const char *program_name)
{
	fprintf(stderr,
	        "사용: sudo %s [옵션] <interface_name> ...\n"
	        "  --ii <file_path>                Table II 출력 (기본 stdout)\n"
	        "  --i  <file_path>                Table I  출력 (기본 stderr)\n"
	        "  -g <gp_ms>                      보고 주기 ms (기본 = 15분)\n"
	        "  --kpm2 <file_path|->            탐지 엔진 kpm2 스트림을 파일로(- = stdout)\n"
	        "  --kpm2-sock <kpm2_socket_path>  탐지 엔진 kpm2 스트림을 유닉스 소켓으로\n"
	        "  --session <session>             kpm2 세션 이름 (기본 portran)\n"
	        "  --node <node_id>                kpm2 hello.node_id\n"
	        "  --ue-evt                        kpm2 에서 Table I ue_evt 줄도 내보냄\n"
	        "\n"
	        "종료 코드: 0 = 정상, 측정 완전 / 1 = 운영 실패(탭, 통계, 스트림) / 2 = 커버리지 불완전\n",
	        program_name);
}

int main(int argc, char **argv)
{
	const char *table_two_path = NULL, *table_one_path = NULL;
	const char *kpm2_file_path = NULL, *kpm2_socket_path = NULL;
	const char *session = NULL, *node_id = NULL;
	bool ue_evt = false;
	uint64_t gp_ms = 0;                      // 0 = libtelemetry 기본값(15분)
	struct cap_interface interfaces[MAX_INTERFACES];
	int interface_count = 0;

	for (int i = 1; i < argc; i++) {
		const char *argument = argv[i];
		bool has_value = i + 1 < argc;
		if      (!strcmp(argument, "--ii")  && has_value) table_two_path   = argv[++i];
		else if (!strcmp(argument, "--i")   && has_value) table_one_path  = argv[++i];
		else if (!strcmp(argument, "-g")    && has_value) {
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
		else if (!strcmp(argument, "--kpm2") && has_value) kpm2_file_path  = argv[++i];
		else if (!strcmp(argument, "--kpm2-sock") && has_value) kpm2_socket_path = argv[++i];
		else if (!strcmp(argument, "--session") && has_value) session      = argv[++i];
		else if (!strcmp(argument, "--node") && has_value) node_id         = argv[++i];
		else if (!strcmp(argument, "--ue-evt")) ue_evt = true;
		else if (argument[0] == '-') { usage(argv[0]); return 2; }
		else {
			if (interface_count >= MAX_INTERFACES) {
				fprintf(stderr, "인터페이스가 너무 많습니다 (상한 %d)\n", MAX_INTERFACES);
				return 2;
			}
			/* 옵션이 아닌 인자는 인터페이스 이름임. argv 는 프로세스가 끝날 때까지 살아 있어
			 *   복사하지 않고 그대로 가리킴. 없는 이름은 cap_open 의 if_nametoindex 가 -ENODEV 로 거름.
			 * role 을 상수로 두는 이유: libcap 이 F1/N2 중 하나를 요구하지만(cap.c 의 인자 검증)
			 *   파이프라인은 이 값을 읽지 않음 - F1AP 와 NGAP 를 가르는 것은 SCTP PPID 임.
			 *   명령행으로 받던 종전 방식은 틀리게 적어도 출력이 같아, 사용자가 잘못을 알 수 없었음 */
			interfaces[interface_count].interface_name = argument;
			interfaces[interface_count].role = CAP_ROLE_F1;
			interface_count++;
		}
	}
	if (interface_count == 0) { usage(argv[0]); return 2; }
	if (kpm2_file_path && kpm2_socket_path) {
		fprintf(stderr, "--kpm2 와 --kpm2-sock 은 함께 쓸 수 없습니다\n");
		return 2;
	}

	/* ── 출력 스트림 열기 ───────────────────────────────────────────────── */
	FILE *table_two_file = stdout, *table_one_file = stderr, *kpm2_stream = NULL;
	if (kpm2_socket_path) {
		kpm2_stream = open_unix_stream(kpm2_socket_path);
		if (!kpm2_stream) return 1;
	} else if (kpm2_file_path) {
		kpm2_stream = !strcmp(kpm2_file_path, "-") ? stdout : fopen(kpm2_file_path, "w");
		if (!kpm2_stream) { perror(kpm2_file_path); return 1; }
	} else {
		if (table_two_path && !(table_two_file = fopen(table_two_path, "w"))) { perror(table_two_path); return 1; }
		if (table_one_path && !(table_one_file = fopen(table_one_path, "w"))) { perror(table_one_path); return 1; }
	}

	// ---- 파이프라인 조립 (아래에서 위로: sink, tr, obs, sctp, cap) ----
	struct pipeline pipeline = { 0 };
	if (kpm2_stream) {
		struct sink_kpm2_cfg kpm2_cfg = {
			.session   = session,
			.producer  = "PortRAN",
			.node_id   = node_id,
			// period_ms 는 gp_ms 와 같은 양의 kpm2 와이어 이름임. ue_evt 모드에선 hello 가 주기보다
			//   먼저 나갈 수 있어 미리 알려 줌.
			//   기본값으로 해소한 값을 넘길 것. 0 을 넘기면 sink_kpm2 가 1 ms 를 지어내고(hello.period_ms=1)
			//   실제 주기는 900000 ms 라, 탐지 엔진이 모든 줄에서 PeriodMismatch 로 전 규칙을 영구
			//   보류함. 기본값 단일출처는 tr.h 임
			.period_ms = gp_ms ? gp_ms : TR_DEF_GP_MS,
			.ue_evt    = ue_evt,
		};
		pipeline.sink = sink_kpm2(kpm2_stream, &kpm2_cfg);
	} else {
		pipeline.sink = sink_jsonl(table_two_file, table_one_file);
	}
	if (!pipeline.sink) {
		fprintf(stderr, "출력 어댑터 초기화 실패 (메모리 부족)\n");
		return 1;
	}
	struct tr_cfg tr_cfg = { .gp_ms = gp_ms };
	pipeline.tr = tr_new(&tr_cfg, &pipeline.sink->ops, pipeline.sink->user_ctx);
	uint32_t late_slack_ms = tr_cfg.late_slack_ms ? tr_cfg.late_slack_ms : TR_DEF_LATE_SLACK_MS;
	struct obs_cfg obs_cfg = { 0 };                 // 전부 0 = libobs 기본값
	pipeline.obs = obs_new(&obs_cfg, on_obs, &pipeline);
	pipeline.sctp = sctp_new(on_message, on_assoc, &pipeline);
	if (!pipeline.tr || !pipeline.obs || !pipeline.sctp) {
		fprintf(stderr, "파이프라인 초기화 실패 (메모리 부족)\n");
		return 1;
	}

	int error = cap_open(interfaces, interface_count, &pipeline.cap);
	if (error) {
		fprintf(stderr, "cap_open: %s (부착은 root 권한이 필요합니다)\n", strerror(-error));
		return 1;
	}

	struct sigaction action = { 0 };
	action.sa_handler = on_signal;
	sigaction(SIGINT, &action, NULL);
	sigaction(SIGTERM, &action, NULL);
	/* SIGPIPE 무시. --kpm2-sock 의 상대인 탐지 엔진이 재시작하면 첫 쓰기에서 SIGPIPE 가 오는데
	 *   기본 동작이 즉사라, cap_detach 부터 tr_finish 까지 종료 경로가 전부 건너뛰어지고 미완
	 *   주기가 사라짐. 무시해 두면 write 가 -EPIPE 로 돌아오고 아래 ferror 검사가 그것을 잡음 */
	struct sigaction ignore_action = { 0 };
	ignore_action.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &ignore_action, NULL);

	fprintf(stderr, "[+] 탭 부착: ");
	for (int i = 0; i < interface_count; i++)
		fprintf(stderr, "%s%s", i ? " " : "", interfaces[i].interface_name);
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
		advance_idle(&pipeline, late_slack_ms);   // 트래픽이 없어도 주기는 닫혀 나가야 함
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
	uint64_t coverage_only_dropped_count = sink_kpm2_coverage_only_dropped_count(pipeline.sink);
	if (coverage_only_dropped_count) {
		fprintf(stderr, "[coverage] 경고: 손실만 있던 주기 %llu 개가 kpm2 규약상 형식이 없어 스트림에 나가지 못했습니다 "
		                "(탐지 엔진이 그 구간을 못 봅니다)\n", (unsigned long long)coverage_only_dropped_count);
		coverage_incomplete = 1;
	}
	uint64_t unknown_direction_dropped_count = sink_kpm2_unknown_direction_dropped_count(pipeline.sink);
	if (unknown_direction_dropped_count) {
		// 정상 망에서는 0 임(RRC 컨테이너를 싣는 F1AP 메시지는 방향이 모두 확정). 0 이 아니면 관측 지점이나 입력 쪽 신호임
		fprintf(stderr, "[coverage] 경고: 방향(UL/DL)을 못 정해 ue_evt 줄 %llu 개를 내보내지 않았습니다 "
		                "(추측해 적지 않습니다 - 비표준 포트나 루프백 관측 지점이거나 기형 입력일 수 있습니다)\n",
		        (unsigned long long)unknown_direction_dropped_count);
		coverage_incomplete = 1;
	}
	uint64_t no_cell_dropped_count = sink_kpm2_no_cell_dropped_count(pipeline.sink);
	if (no_cell_dropped_count) {
		/* 중간합류 UE 는 NR-CGI 를 실은 F1AP 메시지를 못 봐 셀이 미상이고, kpm2 의 ue_evt 는 cell_id 를
		 *   필수로 요구함 -> 줄을 못 냄. 돌아가는 CU 에 탭을 붙이는 정상 배치가 바로 이 경우라,
		 *   조용히 버리면 그 단말이 탐지 엔진에 아예 존재하지 않게 됨 */
		fprintf(stderr, "[coverage] 경고: 셀(NR-CGI)을 못 정해 ue_evt 줄 %llu 개를 내보내지 않았습니다 "
		                "(중간합류 UE - NR-CGI 를 싣는 F1AP 메시지를 탭 부착 전에 놓친 경우입니다)\n",
		        (unsigned long long)no_cell_dropped_count);
		coverage_incomplete = 1;
	}
	uint64_t direction_disagree_count = sink_kpm2_direction_disagree_count(pipeline.sink);
	if (direction_disagree_count) {
		// 줄은 sink 가 고정한 방향으로 나갔음. 0 이 아니면 obs 의 방향 판정이나 합성 경로를 볼 것
		fprintf(stderr, "[coverage] 경고: obs 가 올린 방향이 F1AP 메시지의 확정 방향과 어긋난 ue_evt 줄 %llu 개 "
		                "(줄은 확정 방향으로 나갔습니다 - obs 의 방향 판정이나 grace 만료 합성 경로를 보십시오)\n",
		        (unsigned long long)direction_disagree_count);
		coverage_incomplete = 1;
	}
	uint64_t synthetic_release_skipped_count = sink_kpm2_synthetic_release_skipped_count(pipeline.sink);
	if (synthetic_release_skipped_count) {
		/* 합성분을 와이어에 섞지 않은 것은 설계대로임. 다만 '해제 COMPLETE 를 못 봤다' 는 사실 자체가
		 *   관측 구멍이라 커버리지 불완전으로 표시함 - 형제 경고들과 같은 기준임 */
		fprintf(stderr, "[coverage] 경고: 해제 COMPLETE 를 못 봐 합성한 종료 %llu 건은 ue_evt 로 내보내지 않았습니다 "
		                "(관측한 줄과 섞지 않습니다 - 엔진은 si.RRC.ConnMax 기준 유령 정리로 그 연결을 닫습니다)\n",
		        (unsigned long long)synthetic_release_skipped_count);
		coverage_incomplete = 1;
	}
	uint64_t plmn_mismatch_count = sink_kpm2_plmn_mismatch_count(pipeline.sink);
	if (plmn_mismatch_count) {
		/* cell_id 에 싣는 NR Cell Identity 는 PLMN 안에서만 유일함(TS 38.413 §9.3.1.7). PLMN 이 섞이면
		 *   서로 다른 셀이 같은 cell_id 로 보여 탐지 엔진이 둘을 한 셀로 합쳐 셈. 줄은 나갔으므로
		 *   드롭은 아니지만 지표가 틀렸을 수 있어 커버리지 불완전으로 표시함 */
		fprintf(stderr, "[coverage] 경고: 처음 본 PLMN 과 다른 PLMN 으로 나간 줄이 %llu 개입니다 "
		                "(cell_id 는 PLMN 안에서만 유일해 서로 다른 셀이 같은 값으로 보였을 수 있습니다)\n",
		        (unsigned long long)plmn_mismatch_count);
		coverage_incomplete = 1;
	}
	uint64_t noreply_mismatch_count = sink_kpm2_noreply_mismatch_count(pipeline.sink);
	if (noreply_mismatch_count) {
		fprintf(stderr, "[coverage] 경고: hello 광고 무응답 대기와 실제 적용값이 다른 주기 %llu 개 "
		                "- 탐지 엔진의 시도와 NoReply 매칭이 어긋납니다\n",
		        (unsigned long long)noreply_mismatch_count);
		coverage_incomplete = 1;
	}
	uint64_t cause_omitted_count = sink_kpm2_cause_omitted_count(pipeline.sink);
	if (cause_omitted_count) {
		fprintf(stderr, "[coverage] 경고: Cause 값의 이름을 몰라 ue_evt %llu 줄에서 f.cause 를 생략했습니다 "
		                "(고정 문법이 모르는 값입니다 - 줄 자체는 나갔습니다)\n",
		        (unsigned long long)cause_omitted_count);
		coverage_incomplete = 1;
	}
	uint64_t nas_unmapped_dropped_count = sink_kpm2_nas_unmapped_dropped_count(pipeline.sink);
	if (nas_unmapped_dropped_count) {
		fprintf(stderr, "[coverage] 경고: 엔진 철자표에 없는 5GMM 타입이라 NAS 줄 %llu 개를 내보내지 않았습니다 "
		                "(표 9.7.1 중 어댑터가 아직 안 적은 타입입니다)\n",
		        (unsigned long long)nas_unmapped_dropped_count);
		coverage_incomplete = 1;
	}
	uint64_t capture_unconfirmed_period_count = sink_kpm2_capture_unconfirmed_period_count(pipeline.sink);
	if (capture_unconfirmed_period_count) {
		fprintf(stderr, "[coverage] 경고: 캡처 생사를 확인하지 못해 주기 %llu 개의 카운터를 null 로 보냈습니다 "
		                "(그 구간은 '0건' 이 아니라 '안 셈' 입니다)\n",
		        (unsigned long long)capture_unconfirmed_period_count);
		coverage_incomplete = 1;
	}
	uint64_t nas_f_unnamed_count = sink_kpm2_nas_f_unnamed_count(pipeline.sink);
	if (nas_f_unnamed_count) {
		fprintf(stderr, "[coverage] 경고: 값의 이름을 몰라 NAS 줄의 f 키 %llu 개를 뺐습니다 "
		                "(줄 자체는 나갔습니다 - 엔진에서는 그 IE 가 없었던 것과 같은 모양입니다)\n",
		        (unsigned long long)nas_f_unnamed_count);
		coverage_incomplete = 1;
	}
	uint64_t f1_evt_cells_unknown_count = sink_kpm2_f1_evt_cells_unknown_count(pipeline.sink);
	if (f1_evt_cells_unknown_count) {
		fprintf(stderr, "[coverage] 경고: 재시작 알림 %llu 줄에 셀 목록 대신 '모든 셀' 을 실었습니다 "
		                "(엔진이 그 DU 와 무관한 셀의 단말까지 닫습니다)\n",
		        (unsigned long long)f1_evt_cells_unknown_count);
		coverage_incomplete = 1;
	}
	uint64_t f1_evt_du_ue_id_missing_count = sink_kpm2_f1_evt_du_ue_id_missing_count(pipeline.sink);
	if (f1_evt_du_ue_id_missing_count) {
		fprintf(stderr, "[coverage] 경고: 일부 RESET 의 단말 %llu 개를 번호가 없어 알림에 싣지 못했습니다 "
		                "(엔진이 그만큼 덜 닫습니다)\n",
		        (unsigned long long)f1_evt_du_ue_id_missing_count);
		coverage_incomplete = 1;
	}

	/* 쓰기 오류 검사. 탐지 엔진이 재시작해 소켓이 닫히면 모든 write 가 EPIPE 로 실패하는데,
	 *   fprintf 반환을 버리면 스트림 전체가 조용히 사라진 채 exit 0 으로 나감(= 전량 유실 +
	 *   성공 종료, 가장 나쁜 등급). fclose 반환으로는 못 잡음 - 그쪽은 0 을 돌려줌.
	 *   stdio 가 래치하는 ferror 가 유일한 신호임 */
	struct { FILE *stream; const char *label; } output_streams[] = {
		{ kpm2_stream,     "kpm2" },
		{ table_two_file,  "Table II" },
		{ table_one_file,  "Table I" },
	};
	for (size_t i = 0; i < sizeof output_streams / sizeof output_streams[0]; i++) {
		if (!output_streams[i].stream || !ferror(output_streams[i].stream)) continue;
		fprintf(stderr, "[io] 오류: %s 스트림 쓰기가 실패했습니다 - 그 뒤 내용이 상대에게 닿지 않았습니다 "
		                "(탐지 엔진 재시작, 소켓 닫힘, 디스크 가득 등)\n", output_streams[i].label);
		exit_code = 1;
	}

	cap_close(pipeline.cap);
	sctp_free(pipeline.sctp);
	obs_free(pipeline.obs);
	tr_free(pipeline.tr);
	sink_free(pipeline.sink);
	/* fclose 반환도 검사함. 버퍼에 남은 내용을 내보내다 실패할 수 있고, 그건 위 ferror 뒤에 생길 수도 있음 */
	if (kpm2_stream && kpm2_stream != stdout && fclose(kpm2_stream) != 0) {
		fprintf(stderr, "[io] 오류: kpm2 스트림 닫기 실패: %s (마지막 버퍼가 상대에게 닿지 않았습니다)\n", strerror(errno));
		exit_code = 1;
	}
	if (table_two_file != stdout && fclose(table_two_file) != 0) {
		fprintf(stderr, "[io] 오류: Table II 스트림 닫기 실패: %s\n", strerror(errno));
		exit_code = 1;
	}
	if (table_one_file != stderr && fclose(table_one_file) != 0) {
		fprintf(stderr, "[io] 오류: Table I 스트림 닫기 실패: %s\n", strerror(errno));
		exit_code = 1;
	}
	if (exit_code) return exit_code;                 /* 1 = 운영 실패 */
	return coverage_incomplete ? 2 : 0;              /* 2 = 커버리지 불완전. 둘을 섞지 않음([4]) */
}
