/**
 * cap.c
 * : libcap 로더 - cap.bpf.c 를 커널에 올리고 tcx 에 붙이고, 링 버퍼에서 레코드를 꺼내 공개 API 로 전달
 */
#include <ctype.h>
#include <errno.h>
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

#include <bpf/libbpf.h>
#include "cap.h"
#include "cap_kern_abi.h"
#include "cap.skel.h"

// cap_poll 한 번에 넘기는 최대 레코드 수
// 	폭주로 링 버퍼에 레코드가 잔뜩 쌓여도 한 번에 다 비우지 않음.
#define CAP_POLL_MAX 4096

#define INTERFACE_CHECK_NS 1000000000LL

struct cap_attached_interface {
	uint32_t interface_index;   
	enum cap_interface_role role;
	// lo 인가. ingress/egress 둘 다 붙이면 모든 패킷이 두 번 잡힘
	int loopback; 
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

// (CPU, 훅) 하나당 작업대(scratch) slot 수 결정 (cap.bpf.c 의 slot_count)
// 	보통 커널: 같은 CPU & 같은 훅의 탭이 겹쳐 돌 수 없어 1칸 (CPU 하나당 64KB × 2훅 = 128KB)
// 	PREEMPT_RT 커널: 탭 실행 도중 같은 CPU 의 다른 스레드가 끼어들 수 있어 SLOT_MAX (CPU 하나당 512KB). 
// 	칸이 모자라 겹친 실행은 레코드를 버리고 slot_busy_count + ringbuf_full_count 로 센다 (섞인 레코드는 절대 나가지 않음).
//  	몇 칸까지 실제로 쓰이는지는 cap_stats.slot_used_count[] 로 보인다 → SLOT_MAX 는 실측으로 조정할 값이다.
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

// libbpf 가 링 버퍼 레코드 하나마다 callback 하는 함수 (ring_buffer__new 에 등록)
// 	ctx  = ring_buffer__new 에 넘긴 struct cap
// 	ringbuf_record = 레코드 시작 주소. 링 버퍼 메모리를 그대로 가리킨다 (복사 없음)
//   	size_bytes   = 레코드 크기 = 커널이 bpf_ringbuf_output 에 준 크기 (머리 40B + captured_len)
static int on_ringbuf_record(void *ctx, void *ringbuf_record, size_t size_bytes) {
	struct cap *cap = ctx;
	const struct cap_event *kernel_event = ringbuf_record;

	// 크기 검증: 정상 커널이면 항상 통과하지만, 레코드 경계 밖을 읽는 일은 절대 없게 한 번 더 확인
	if (size_bytes < sizeof(kernel_event->hdr) || kernel_event->hdr.captured_len > MAX_CAP_BYTES || sizeof(kernel_event->hdr) + kernel_event->hdr.captured_len > size_bytes) {
		cap->bad_record_count++;
		return 0;
	}

	// TAI→UTC 차이를 쓰기 직전에 다시 읽기. 이 배치의 첫 레코드에서만(아래 변환이 처음 쓰는 지점) 한 번.
	if (cap->poll.delivered_count == 0)
		refresh_tai_offset(cap);

	// 커널 레코드(event) → 공개 API 레코드(cap_record)
	struct cap_record record = {
		// TAI -> 벽시계(UTC)
		.capture_time_ns = (uint64_t)((int64_t)kernel_event->hdr.capture_tai_ns - cap->tai_offset_ns),  
		.interface_index = kernel_event->hdr.interface_index,
		.capture_hook    = (enum cap_hook)kernel_event->hdr.capture_hook,  
		.src_addr        = kernel_event->hdr.src_addr,
		.dst_addr        = kernel_event->hdr.dst_addr,
		.src_port        = kernel_event->hdr.src_port,
		.dst_port        = kernel_event->hdr.dst_port,
		// 링 버퍼 메모리를 그대로 빌려줌 → 콜백이 끝나면 커널이 덮어쓸 수 있음
		.sctp_packet     = kernel_event->sctp_packet,
		.captured_len    = kernel_event->hdr.captured_len,
		.packet_len      = kernel_event->hdr.packet_len,
	};
	cap->poll.record_cb(cap->poll.user_ctx, &record);
	cap->poll.delivered_count++;

	return cap->poll.delivered_count >= CAP_POLL_MAX ? -EAGAIN : 0;
}

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

	// 인자 검증: 잘못된 입력에 BPF load 를 하지 않기 위함
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

	// BPF 오브젝트 설정
	// 	skeleton 안에 내장된 cap.bpf.o 파싱
	cap->bpf_skeleton = cap_bpf__open();
	if (!cap->bpf_skeleton) {
		error = negative_errno();
		goto fail;
	}

	// scratch 를 (CPU 번호 상한 × HOOK_COUNT × 칸 수) 로 늘리는 작업
	// 	안 늘리면 CPU 1 이상에서 잡힌 패킷은 칸을 찾지 못함 (커널이 slot_busy_count + ringbuf_full_count 로 셈)
	// 	칸 수(slot_count)는 .rodata => 커널에 올리기 전에만 수정 가능
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

	// 커널에 전달 -> verifier 검사
	error = cap_bpf__load(cap->bpf_skeleton);
	if (error)
		goto fail;

	// 인터페이스마다 tcx 에 부착
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

	// Ring Buffer consumer : ringbuf 맵에 레코드가 들어오면 on_ringbuf_record(cap, ...) 가 callback
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

static void detach_one(struct bpf_link **attach_ptr) {
	if (!*attach_ptr)
		return;
	bpf_link__detach(*attach_ptr);
	bpf_link__destroy(*attach_ptr);
	// 이중 해제 금지
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

// cap_close: cap_open 이 만든 것을 모두 해제. 
// 	정리 순서: consumer -> detach -> program & map 해제
void cap_close(struct cap *cap) {
	if (!cap)
		return;
	ring_buffer__free(cap->ringbuf);
	cap_detach(cap);
	cap_bpf__destroy(cap->bpf_skeleton);
	free(cap->attached_interfaces);
	free(cap);
}
