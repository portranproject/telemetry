/**
 * cap.c
 * : libcap 로더 - cap.bpf.c 를 커널에 올리고 tcx 에 붙이고, 링 버퍼에서 레코드를 꺼내 공개 API 로 전달
 */
#include <stdlib.h>
#include <bpf/libbpf.h>
#include "cap.h"
#include "cap_kern_abi.h"
#include "cap.skel.h"

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
		// user callback
		cap_record_cb record_cb;
		// 콜백 첫 인자로 그대로 넘길 포인터(호출한 쪽 소유)
		void *user_ctx;
		// 이번 cap_poll 에서 넘긴 레코드 수
		int delivered_count; 
	} poll;
};

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

/* cap_close: cap_open 이 만든 것을 모두 해제. 
 *   정리 순서: consumer -> detach -> program & map 해제
 */
void cap_close(struct cap *cap) {
	if (!cap)
		return;
	ring_buffer__free(cap->ringbuf);
	cap_detach(cap);
	cap_bpf__destroy(cap->bpf_skeleton);
	free(cap->attached_interfaces);
	free(cap);
}


