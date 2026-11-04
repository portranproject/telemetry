/**
 * cap.c
 * : libcap 로더 - cap.bpf.c 를 커널에 올리고 tcx 에 붙이고, 링 버퍼에서 레코드를 꺼내 공개 API 로 전달
 *
 * [1] tcx 핸들의 생명주기. 
 *     (none) --cap_open--> [attach] --cap_detach--> [detach] --cap_close--> (none)
 *
 *                             [attach] [detach]
 *       cap_poll                  O       O     링 버퍼에 남은 레코드는 detach 후에도 추출됨
 *       cap_get_stats             O       O     bpf map 은 skeleton 에 남아 있기 때문
 *       cap_get_interface_role    O       O     attached_interfaces 를 훑음
 *       새 레코드 유입            O       X     tap() 이 동작하지 않기 때문
 *
 * [2] cap_open / cap_close 
 *
 *       cap_open                                        cap_close
 *       --------------------------------------------    --------------------------
 *       calloc x2    핸들과 attached_interfaces         <----- 4. free(attached_interfaces)
 *                                                       <----- 5. free(cap)
 *       1. 검증      이름 -> 번호, 중복, L2 종류
 *       2. 파싱      cap_bpf__open                      <--+
 *       3. 설정      rodata.slot_count, scratch 크기       |   3. cap_bpf__destroy
 *       4. 로드      cap_bpf__load -> verifier          <--+    
 *       5. 부착      tcx ingress / egress               <----- 2. cap_detach
 *       6. consumer  ring_buffer__new                   <----- 1. ring_buffer__free
 *
 * [3] cap_poll 에 의한 호출. cap_poll 이 아닌 libbpf 가 on_ringbuf_record 를 직접 호출.
 *     	libbpf 는 ring_buffer__new 때 고정한 ctx 하나만 넘기고 ring_buffer__poll
 *     	에는 ctx 를 넘길 자리가 없어서, 호출자 콜백을 cap->poll 에 적어 두고 거기서 읽음.
 *
 *       main.c                        libcap                      libbpf / 커널
 *       ---------------------------------------------------------------------------
 *       cap_poll(cap, 200, on_record, &pipeline)
 *         |
 *         +-- interfaces_lost()              
 *         +-- cap->poll = {on_record, &pipeline, 0}
 *         +-- ring_buffer__poll(cap->ringbuf, wait_ms) ---->  epoll 대기
 *                                                                   |  레코드 도착
 *         |   on_ringbuf_record(cap, ringbuf_record, size_bytes) <--+  libbpf 의 호출
 *         |     +-- 크기 검증 3개              실패 -> bad_record_count
 *         |     +-- refresh_tai_offset()       이번 cap_poll 의 첫 레코드에서만 진행
 *         |     +-- cap_event -> cap_record    TAI -> UTC
 *         |     +-- cap->poll.record_cb(cap->poll.user_ctx, &record)
 *         |           |
 *         |           +-- on_record(&pipeline, record) - main 함수
 *         |           (레코드가 더 남은 경우 libbpf 가 재호출. CAP_POLL_MAX 까지)
 *         |
 *         +-- cap->poll.record_cb = NULL
 *         v
 *       delivered_count
 */

#include <ctype.h>
#include <errno.h>
#include <sched.h>
#include <stdbool.h> 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h> 
#include <unistd.h> 
#include <net/if.h> 
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h> 
#include <sys/timex.h>
#include <sys/utsname.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "cap.h"
#include "cap_kern_abi.h"
#include "cap.skel.h"

// cap_poll 한 번에 넘기는 최대 레코드 수
// 	폭주로 링 버퍼에 레코드가 잔뜩 쌓여도 한 번에 다 비우지 않음.
#define CAP_POLL_MAX 4096

// 붙여 둔 인터페이스가 아직 살아 있는지 확인하는 간격 (1초).
#define INTERFACE_CHECK_NS 1000000000LL

struct cap_attached_interface {
	uint32_t interface_index;   
	enum cap_interface_role role;
	// lo 인가. ingress/egress 둘 다 붙이면 모든 패킷이 두 번 잡히기 때문
	bool loopback; 
	struct bpf_link *ingress_attach;
	struct bpf_link *egress_attach;
};

struct cap {
 	// skeleton: 커널에 올린 프로그램 2개와 맵 3개(ringbuf/scratch/stats)를 묶어 관리
	struct cap_bpf *bpf_skeleton;
	// libbpf Ring Buffer consumer: ringbuf 맵에서 레코드를 꺼내 on_ringbuf_record 호출
	struct ring_buffer *ringbuf;
	struct cap_attached_interface *attached_interfaces;
	int interface_count;
	// 커널 TAI 시각 - 벽시계(UTC) 차이(ns). 
	// 	레코드마다 adjtimex 호출하지 않게 위해 캐싱
	int64_t tai_offset_ns; 
	// 다음에 인터페이스 생존을 확인할 시각(CLOCK_MONOTONIC ns).
	int64_t next_interface_check_ns;
	// 유저공간이 크기 검증에서 버린 레코드 수
	uint64_t bad_record_count;
	// cap_poll 한 번이 도는 동안에만 유효한 상태.
	// 	libbpf 콜백은 ring_buffer__new 때 고정된 ctx 포인터 하나로만 호출됨
	// 	cap_poll 의 인자(콜백/사용자 포인터)를 전달할 통로가 없음 
	// 	-> 핸들에 넣고 콜백이 꺼내 사용. 
	struct {
		cap_record_cb record_cb;
		void *user_ctx;
		int delivered_count; 
	} poll;
};

static int negative_errno(void) {
	return errno ? -errno : -EIO;
}

static int64_t monotonic_ns(void) {
	struct timespec monotonic_time;
	clock_gettime(CLOCK_MONOTONIC, &monotonic_time);
	return (int64_t)monotonic_time.tv_sec * 1000000000LL + monotonic_time.tv_nsec;
}

// 커널 TAI 시각을 벽시계(UTC)로 바꿀 차이값 계산
static void refresh_tai_offset(struct cap *cap) {
	struct timex timex_info;
	memset(&timex_info, 0, sizeof(timex_info));
	if (adjtimex(&timex_info) >= 0) {
		cap->tai_offset_ns = (int64_t)timex_info.tai * 1000000000LL;
		return;
	}
	struct timespec tai_time;
	struct timespec utc_time;
	if (clock_gettime(CLOCK_TAI, &tai_time) || clock_gettime(CLOCK_REALTIME, &utc_time))
		return;
	int64_t diff_ns = ((int64_t)tai_time.tv_sec - utc_time.tv_sec) * 1000000000LL + ((int64_t)tai_time.tv_nsec - utc_time.tv_nsec);
	int64_t tai_offset_seconds = (diff_ns + (diff_ns >= 0 ? 500000000LL : -500000000LL)) / 1000000000LL;
	cap->tai_offset_ns = tai_offset_seconds * 1000000000LL;
}

// read_cpu_id_limit : 커널이 쓸 수 있는 가장 큰 CPU 번호 + 1 
// 	(= bpf_get_smp_processor_id 가 돌려줄 수 있는 값의 개수)
// 	/sys/devices/system/cpu/possible 은 "0-3" 이나 "0,2-5" 처럼 적혀 있음. 가장 큰 숫자 + 1.
static int read_cpu_id_limit(void) {
	FILE *file = fopen("/sys/devices/system/cpu/possible", "re");
	if (!file)
		return negative_errno();
	char buf[4096];
	char *line = fgets(buf, sizeof(buf), file);
	fclose(file);
	if (!line)
		return -EIO;
	long max_cpu_id = -1;
	for (char *text_cursor = buf; *text_cursor; ) {
		if (isdigit((unsigned char)*text_cursor)) {
			long parsed_cpu_id = strtol(text_cursor, &text_cursor, 10);   
			if (parsed_cpu_id > max_cpu_id)
				max_cpu_id = parsed_cpu_id;
		} else {
			text_cursor++;
		}
	}
	if (max_cpu_id < 0)
		return -EIO;
	if (max_cpu_id >= 8192)
		return -ERANGE;
	return (int)max_cpu_id + 1;
}

// 지금 커널이 PREEMPT_RT 인지 확인
static bool kernel_is_realtime(void) {
	struct utsname uname_info;
	if (uname(&uname_info) == 0 && strstr(uname_info.version, "PREEMPT_RT"))
		return true;
	FILE *file = fopen("/sys/kernel/realtime", "re");
	if (!file)
		return false;
	bool is_realtime = fgetc(file) == '1';
	fclose(file);
	return is_realtime;
}

// read_slot_count : CPU, 훅 하나당 작업대(scratch) slot 수 결정 (cap.bpf.c 의 slot_count)
// 	보통 커널: 같은 CPU & 같은 훅의 탭이 겹쳐 돌 수 없어 1칸 (CPU 하나당 64KB × 2훅 = 128KB)
// 	PREEMPT_RT 커널: 탭 실행 도중 같은 CPU 의 다른 스레드가 끼어들 수 있어 SLOT_MAX (CPU 하나당 512KB). 
// 	칸이 모자라 겹친 실행은 레코드를 버리고 slot_busy_count + ringbuf_full_count 로 셈 (섞인 레코드는 절대 나가지 않음).
//  	몇 칸까지 실제로 쓰이는지는 cap_stats.slot_used_count[] 로 보임
static __u32 read_slot_count(void) {
	const char *slot_count_text = getenv("CAP_SLOT_COUNT");
	if (slot_count_text) {
		long parsed_slot_count = strtol(slot_count_text, NULL, 10);
		if (parsed_slot_count >= 1 && parsed_slot_count <= SLOT_MAX)
			return (__u32)parsed_slot_count;
	}
	return kernel_is_realtime() ? SLOT_MAX : 1;
}

enum cap_l2_kind {
	// ARPHRD_ETHER: NIC / veth / bridge - 14B Ethernet 헤더 존재
	CAP_L2_ETHERNET,           
	// ARPHRD_LOOPBACK: lo. 헤더는 있으나 한 패킷이 egress 와 ingress 를 둘 다 지남
	CAP_L2_LOOPBACK,
};

// 인터페이스의 L2 종류를 확인 (cap.bpf.c 의 tap 은 14B Ethernet 머리를 전제)
static int check_l2(const char *interface_name, enum cap_l2_kind *l2_kind_out) {
	struct ifreq ifreq_info;
	memset(&ifreq_info, 0, sizeof(ifreq_info)); 
	strncpy(ifreq_info.ifr_name, interface_name, IFNAMSIZ - 1);
	int socket_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (socket_fd < 0)
		return negative_errno();
	// 하드웨어 주소 종류(ARPHRD_*)를 읽음
	int error = ioctl(socket_fd, SIOCGIFHWADDR, &ifreq_info) < 0 ? negative_errno() : 0;  
	close(socket_fd);
	if (error)
		return error;
	switch (ifreq_info.ifr_hwaddr.sa_family) {
	case ARPHRD_ETHER:    *l2_kind_out = CAP_L2_ETHERNET;  return 0;
	case ARPHRD_LOOPBACK: *l2_kind_out = CAP_L2_LOOPBACK;  return 0;
	default:              return -EOPNOTSUPP;
	}
}

/* on_ringbuf_record: 링 버퍼 레코드 하나를 공개 API 형식으로 바꿔 호출자 콜백에 넘김.
 *   ring_buffer__new 에 등록해 두고 libbpf 가 레코드마다 호출하는 구조. ctx 는 거기서 고정한 struct cap,
 *   ringbuf_record 는 링 버퍼 메모리를 그대로 가리키고(복사 없음), size_bytes 는 커널이
 *   bpf_ringbuf_output 에 준 크기.
 *
 *     0                                40        40 + captured_len <= size_bytes
 *     +--------------------------------+---------------------------+
 *     | cap_event_header               | sctp_packet               |
 *     +--------------------------------+---------------------------+
 *     |<----------- 검사 1 ----------->|                           |
 *     |<------------------------ 검사 3 -------------------------->|
 *                                        검사 2: captured_len <= MAX_CAP_BYTES
 */
static int on_ringbuf_record(void *ctx, void *ringbuf_record, size_t size_bytes) {
	struct cap *cap = ctx;
	const struct cap_event *kernel_event = ringbuf_record;

	if (size_bytes < sizeof(kernel_event->header) || kernel_event->header.captured_len > MAX_CAP_BYTES || sizeof(kernel_event->header) + kernel_event->header.captured_len > size_bytes) {
		cap->bad_record_count++;
		return 0;
	}

	// TAI -> UTC 차이를 쓰기 직전에 다시 읽기. 이 배치의 첫 레코드에서만 수행.
	if (cap->poll.delivered_count == 0)
		refresh_tai_offset(cap);

	struct cap_record record = {
		// TAI -> 벽시계(UTC)
		.capture_time_ns = (uint64_t)((int64_t)kernel_event->header.capture_tai_ns - cap->tai_offset_ns),  
		.interface_index = kernel_event->header.interface_index,
		.capture_hook    = (enum cap_hook)kernel_event->header.capture_hook,  
		.src_addr        = kernel_event->header.src_addr,
		.dst_addr        = kernel_event->header.dst_addr,
		.src_port        = kernel_event->header.src_port,
		.dst_port        = kernel_event->header.dst_port,
		// 링 버퍼 메모리를 그대로 빌려줌 -> 콜백이 끝나면 커널이 덮어쓸 수 있음.
		.sctp_packet     = kernel_event->sctp_packet,
		.captured_len    = kernel_event->header.captured_len,
		.packet_len      = kernel_event->header.packet_len,
	};
	cap->poll.record_cb(cap->poll.user_ctx, &record);
	cap->poll.delivered_count++;

	return cap->poll.delivered_count >= CAP_POLL_MAX ? -EAGAIN : 0;
}

/* cap_open: 인터페이스 목록을 받아 커널 탭을 올려 붙이고, 레코드를 꺼낼 핸들 하나를 만듬.
 * 	반환: 0 이면 성공(*cap_out 에 핸들)
 *      -EINVAL      cap_out / interfaces 가 NULL, interface_count <= 0, 이름이 NULL, role 이 F1/N2 가 아님
 *      -ENOMEM      핸들 / attached_interfaces 할당 실패
 *      -ENODEV      그 이름의 인터페이스가 없음
 *      -EEXIST      같은 인터페이스를 두 번 줌 (모든 패킷이 두 번 잡히므로 거부)
 *      -EOPNOTSUPP  Ethernet 헤더가 없는 장치 (check_l2)
 *      그 밖        libbpf / verifier / 부착 실패의 errno
 */
int cap_open(const struct cap_interface *interfaces, int interface_count, struct cap **cap_out) {
	if (!cap_out)
		return -EINVAL;
	*cap_out = NULL;                  
	if (!interfaces || interface_count <= 0)
		return -EINVAL;

	struct cap *cap = calloc(1, sizeof(*cap));
	if (!cap)
		return -ENOMEM;
	cap->attached_interfaces = calloc((size_t)interface_count, sizeof(*cap->attached_interfaces));
	if (!cap->attached_interfaces) {
		free(cap);
		return -ENOMEM;
	}
	cap->interface_count = interface_count;

	int error;

	// 1) 인자 검증: 잘못된 입력에 BPF load 를 하지 않기 위함
	for (int i = 0; i < interface_count; i++) {
		struct cap_attached_interface *attached_interface = &cap->attached_interfaces[i];
		if (!interfaces[i].interface_name ||
		    (interfaces[i].role != CAP_ROLE_F1 && interfaces[i].role != CAP_ROLE_N2)) {
			error = -EINVAL;
			goto fail;
		}
		attached_interface->role = interfaces[i].role;
		attached_interface->interface_index = if_nametoindex(interfaces[i].interface_name);
		if (!attached_interface->interface_index) {
			error = -ENODEV;
			goto fail;
		}
		for (int j = 0; j < i; j++) {
    			// 같은 인터페이스를 두 번 붙이면 모든 패킷이 두 번 잡힘
			if (cap->attached_interfaces[j].interface_index == attached_interface->interface_index) {
				error = -EEXIST;
				goto fail;
			}
		}
		enum cap_l2_kind l2_kind;
		error = check_l2(interfaces[i].interface_name, &l2_kind);
		if (error)
			goto fail;
		attached_interface->loopback = (l2_kind == CAP_L2_LOOPBACK);
	}
	// 2) skeleton 안에 내장된 cap.bpf.o 파싱
	cap->bpf_skeleton = cap_bpf__open();
	if (!cap->bpf_skeleton) {
		error = negative_errno();
		goto fail;
	}
	 // 3) scratch 를 cpu_id_limit x HOOK_COUNT x slot_count 로 늘린다.
	int cpu_id_limit = read_cpu_id_limit();
	if (cpu_id_limit <= 0) {
		error = cpu_id_limit < 0 ? cpu_id_limit : -EIO;
		goto fail;
	}
	__u32 slot_count = read_slot_count();
	cap->bpf_skeleton->rodata->slot_count = slot_count;
	error = bpf_map__set_max_entries(cap->bpf_skeleton->maps.scratch, (__u32)cpu_id_limit * HOOK_COUNT * slot_count);
	if (error)
		goto fail;

	// 4) 커널에 전달 -> verifier 검사
	error = cap_bpf__load(cap->bpf_skeleton);
	if (error)
		goto fail;
	// 5) 인터페이스마다 tcx에 부착
	LIBBPF_OPTS(bpf_tcx_opts, tcx_attach_options, .flags = BPF_F_BEFORE);
	for (int i = 0; i < interface_count; i++) {
		struct cap_attached_interface *attached_interface = &cap->attached_interfaces[i];
		attached_interface->ingress_attach = bpf_program__attach_tcx(cap->bpf_skeleton->progs.capture_tc_ingress, (int)attached_interface->interface_index, &tcx_attach_options);
		if (!attached_interface->ingress_attach) {
			error = negative_errno();
			goto fail;
		}
		// lo: 나가는 패킷이 곧바로 다시 들어오므로 ingress 하나면 충분
		if (attached_interface->loopback)
			continue;
		attached_interface->egress_attach = bpf_program__attach_tcx(cap->bpf_skeleton->progs.capture_tc_egress, (int)attached_interface->interface_index, &tcx_attach_options);
		if (!attached_interface->egress_attach) {
			error = negative_errno();
			goto fail;
		}
	}

	// 6) Ring Buffer consumer : ringbuf 맵에 레코드가 들어오면 on_ringbuf_record(cap, ...) 가 호출됨
	cap->ringbuf = ring_buffer__new(bpf_map__fd(cap->bpf_skeleton->maps.ringbuf), on_ringbuf_record, cap, NULL);
	if (!cap->ringbuf) {
		error = negative_errno();
		goto fail;
	}

	// 단, TAI 차이는 첫 레코드 때 on_ringbuf_record 가 읽음(여기선 초기화 불필요)
	cap->next_interface_check_ns = monotonic_ns() + INTERFACE_CHECK_NS;  
	*cap_out = cap;
	return 0;

fail:
	cap_close(cap);
	return error;
}

// 부착 하나가 아직 인터페이스에 붙어 있는지 확인
static bool attach_alive(struct bpf_link *attach) {
	if (!attach)
		return true; 
	struct bpf_link_info link_info;
	__u32 link_info_len = sizeof(link_info);
	memset(&link_info, 0, sizeof(link_info));
	if (bpf_link_get_info_by_fd(bpf_link__fd(attach), &link_info, &link_info_len))
		return true;  
	return link_info.tcx.ifindex != 0;
}

// 붙여 둔 인터페이스가 하나라도 사라졌는지 확인
static bool interfaces_lost(struct cap *cap) {
	int64_t now_ns = monotonic_ns();
	if (now_ns < cap->next_interface_check_ns)
		return false;
	cap->next_interface_check_ns = now_ns + INTERFACE_CHECK_NS;
	for (int i = 0; i < cap->interface_count; i++)
		if (!attach_alive(cap->attached_interfaces[i].ingress_attach) || !attach_alive(cap->attached_interfaces[i].egress_attach))
			return true;
	return false;
}

/* cap_poll: 링 버퍼에 쌓인 레코드를 꺼내 record_cb 로 넘김. 최대 CAP_POLL_MAX 개.
 *   	기다릴 때는 timeout_ms 를 한 번에 자지 않고 생존 확인 시점에서 끊어 잘게 나눔 (timeout_ms = 2500 예):
 *
 *     now_ns                                    deadline_ns
 *       |--- <=1000ms ---|---- 1000ms ----|---- 500ms ----|
 *       ^                ^                ^               ^
 *       |                |                |               +-- 기한. 확인하지 않고 바로 리턴
 *       |                +----------------+-- 깨어나 interfaces_lost() 로 확인
 *       +-- 들어올 때. 확인 주기가 지났으면 확인하고 ring_buffer__poll(wait_ms) 로 sleep
 */
int cap_poll(struct cap *cap, int timeout_ms, cap_record_cb record_cb, void *user_ctx) {
	if (!cap || !cap->ringbuf || !record_cb) 
		return -EINVAL;
	if (cap->poll.record_cb)
		return -EBUSY;
	if (interfaces_lost(cap))
		return -ENODEV;

	cap->poll.record_cb = record_cb;
	cap->poll.user_ctx = user_ctx;
	cap->poll.delivered_count = 0;

     	// ring_buffer__consume/poll 반환: ≥0 = 꺼낸 레코드 수, <0 = errno (libbpf 규약)
	int poll_result;

	if (timeout_ms == 0) {
		// no wait: epoll 을 거치지 않고 링 버퍼의 쓰기 및 읽기 위치를 직접 비교해 있는 만큼 가져옴.
		poll_result = ring_buffer__consume(cap->ringbuf);
	} else {
		// wait: 인터페이스 확인 시점(1초 간격)을 넘겨 한 번에 잠들지 않게 잘게 나눠 기다림
		// 	-> timeout_ms 가 -1(끝없이)이어도 인터페이스가 사라지면 1초 안에 -ENODEV 로 알림
		int64_t deadline_ns = timeout_ms > 0 ? monotonic_ns() + (int64_t)timeout_ms * 1000000LL : INT64_MAX;
		for (;;) {
			int64_t now_ns = monotonic_ns();
			int64_t until_ns = cap->next_interface_check_ns < deadline_ns ? cap->next_interface_check_ns : deadline_ns;
			// ns -> ms
			int wait_ms = until_ns > now_ns ? (int)((until_ns - now_ns + 999999) / 1000000) : 0;
		   	// epoll 로 기다렸다가 쌓인 레코드마다 on_ringbuf_record 호출
			poll_result = ring_buffer__poll(cap->ringbuf, wait_ms);

			// 꺼낸 것이 있거나(>0), 신호/상한/오류(<0)
			if (poll_result != 0 || cap->poll.delivered_count > 0)
				break;
			if (monotonic_ns() >= deadline_ns)
				break;
			if (interfaces_lost(cap)) {
				poll_result = -ENODEV;
				break;
			}
			// ring_buffer__poll 이 준 0 에는 두 가지가 섞여 있음
                        // 	(a) 링 버퍼가 진짜 비었다          
			// 		-> epoll 이 wait_ms 만큼 지난 경우
                        //     	(b) 맨 앞 레코드를 커널이 쓰는 중  
			//     		-> epoll 이 자지 않고 즉시 돌아온 경우
                        //
                        // (b) 의 원인: 커널은 자리를 예약할 때 producer_pos 를 먼저 올리고 BUSY 는 나중에 제거.
                        //        커널 (bpf_ringbuf_output)           현재 루프
                        //        -------------------------           --------------
                        //   +--  hdr->len = size|BUSY                <- BUSY 윈도우 시작
                        //   |    producer_pos += len                 epoll_wait -> 즉시 반환 (readable)
                        //   |                                          커널 poll 은 producer_pos 만 확인
                        //   |    memcpy(rec, data, size)             libbpf -> 맨 앞이 BUSY 라 0개
                        //   |      (최대 64KB)                       poll_result=0, delivered_count=0
                        //   |      RT 면 이 안에서 선점 가능         sched_yield()      <-- 여기
                        //   +--  hdr->len ^= BUSY  (commit)          <- 닫힌다
                        //                                            epoll_wait -> 1개! on_ringbuf_record
			// BUSY 윈도우가 열려 있는 동안, commit 될 때까지 CPU 를 계속 사용하기 때문.
			sched_yield();
		}
	}
	// 비워야 다음 호출이 -EBUSY 에 걸리지 않음(구현 확인)
	cap->poll.record_cb = NULL;
	cap->poll.user_ctx = NULL;
	// -EINTR : 기다리는 중 신호(Ctrl+C 등)가 옴
	// -EAGAIN: on_ringbuf_record 가 CAP_POLL_MAX 에서 스스로 멈춤
	if (poll_result < 0 && poll_result != -EINTR && poll_result != -EAGAIN)
		return poll_result;
	return cap->poll.delivered_count;
}

/* cap_get_stats: 커널 카운터를 모두 더해 공개 통계로 채움.
 *   이유: stats 는 PERCPU_ARRAY. 커널이 CPU 간 경쟁 없이 세는 대신, 읽는 쪽이 CPU 수만큼 더함.
 *
 *     key = ST_CAPTURED  ->  values[0] values[1] ... values[cpu_count-1]
 *                            +--------- 다 더해서 ---------------------+
 *                                       captured_count
 */
int cap_get_stats(const struct cap *cap, struct cap_stats *stats_out) {
	if (!stats_out)
		return -EINVAL;
	memset(stats_out, 0, sizeof(*stats_out));
	if (!cap || !cap->bpf_skeleton)
		return -EINVAL;
	// 유저공간에서 버린 깨진 레코드도 truncated_count 에 합산
	stats_out->truncated_count = cap->bad_record_count;                     
	_Static_assert(ST_COUNT == 10, "ST_* 가 바뀌면 아래 표도 고칠 것");
	_Static_assert(SLOT_MAX == 4, "SLOT_MAX 가 바뀌면 아래 slot_used_count 줄 수도 고칠 것");
    	
	// stat_fields[] 의 줄 순서: slot_busy_count 를 ringbuf_full_count 보다 먼저 읽음.
    	// 	커널은 slot 부족 때 ST_SLOT_BUSY 를 먼저, ST_RINGBUF_FULL 을 나중에 셈(cap.bpf.c 의 두 bump).
    	//   	이 순서면 두 값이 어긋날 창이 그 두 bump 사이로 줄어듬. 다만 두 bump 는 원자적이지 않아
    	//   	slot_busy_count <= ringbuf_full_count 가 보장되지는 않음
	const struct { __u32 stat_index; uint64_t *dst; } stat_fields[] = {
		{ ST_CAPTURED, &stats_out->captured_count },
		{ ST_SLOT_BUSY,     &stats_out->slot_busy_count },
		{ ST_RINGBUF_FULL,  &stats_out->ringbuf_full_count },
		{ ST_TRUNCATED,    &stats_out->truncated_count },
		{ ST_IP_FRAG_SKIPPED,   &stats_out->ip_frag_skipped_count },
		{ ST_ESP_SEEN,      &stats_out->esp_seen_count },
		{ ST_SLOT_USED_BASE + 0, &stats_out->slot_used_count[0] },
		{ ST_SLOT_USED_BASE + 1, &stats_out->slot_used_count[1] },
		{ ST_SLOT_USED_BASE + 2, &stats_out->slot_used_count[2] },
		{ ST_SLOT_USED_BASE + 3, &stats_out->slot_used_count[3] },
	};

	int cpu_count = libbpf_num_possible_cpus();
	if (cpu_count <= 0)
		return cpu_count < 0 ? cpu_count : -EIO;
	__u64 *values = calloc((size_t)cpu_count, sizeof(*values));
	if (!values)
		return -ENOMEM;

	int error = 0;
	int stats_map_fd = bpf_map__fd(cap->bpf_skeleton->maps.stats);
	for (size_t i = 0; i < sizeof(stat_fields) / sizeof(stat_fields[0]); i++) {
		if (bpf_map_lookup_elem(stats_map_fd, &stat_fields[i].stat_index, values)) {
			error = negative_errno();
			continue;
		}
		for (int value_index = 0; value_index < cpu_count; value_index++)
			*stat_fields[i].dst += values[value_index];
	}
	free(values);
	if (error)  
		memset(stats_out, 0, sizeof(*stats_out));         
	return error;
}

enum cap_interface_role cap_get_interface_role(const struct cap *cap, uint32_t interface_index) {
	if (cap) {
		for (int i = 0; i < cap->interface_count; i++) {
			if (cap->attached_interfaces[i].interface_index == interface_index)
				return cap->attached_interfaces[i].role;
		}
	}
	return CAP_ROLE_UNKNOWN;
}

static void detach_one(struct bpf_link **attach_ptr) {
	if (!*attach_ptr)
		return;
	bpf_link__detach(*attach_ptr);
	bpf_link__destroy(*attach_ptr);
	*attach_ptr = NULL;
}

void cap_detach(struct cap *cap) {
	if (!cap || !cap->attached_interfaces)
		return;
	for (int i = 0; i < cap->interface_count; i++) {
		detach_one(&cap->attached_interfaces[i].ingress_attach);
		detach_one(&cap->attached_interfaces[i].egress_attach);
	}
}

void cap_close(struct cap *cap) {
	if (!cap)
		return;
	ring_buffer__free(cap->ringbuf);
	cap_detach(cap);
	cap_bpf__destroy(cap->bpf_skeleton);
	free(cap->attached_interfaces);
	free(cap);
}
