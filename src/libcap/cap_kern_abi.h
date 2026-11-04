/**
 * cap_kern_abi.h 
 * : libcap 비공개 헤더 파일, 커널(cap.bpf.c) <-> 로더(cap.c) 간 데이터 전달 형식 정의
 */

#ifndef TELEMETRY_CAP_KERN_ABI_H
#define TELEMETRY_CAP_KERN_ABI_H

#include <linux/types.h>

// sctp_packet[] 상한
#define MAX_CAP_BYTES 65536 
_Static_assert((MAX_CAP_BYTES & (MAX_CAP_BYTES - 1)) == 0, "MAX_CAP_BYTES 는 2의 거듭제곱이어야 한다 (복사 길이 증명이 & (MAX_CAP_BYTES-1) 로 상한을 세운다)");

#define HOOK_TC_INGRESS 0
#define HOOK_TC_EGRESS 1
#define HOOK_COUNT 2

// (CPU, HOOK) 이 동시에 점유할 수 있는 slot 수 = 
// 	PREEMPT_RT nesting 깊이 상한 (보통 커널은 1칸)
#define SLOT_MAX 4

// cap_event_hdr.flags (captured_len < packet_len)
#define EVENT_TRUNCATED 0x1

// +--------+------------+---------+---------------+--------+---------+---+---+---+---+
// |CAPTURED|RINGBUF_FULL|TRUNCATED|IP_FRAG_SKIPPED|ESP_SEEN|SLOT_BUSY| 0 | 1 | 2 | 3 |
// +--------+------------+---------+---------------+--------+---------+---+---+---+---+
//                                                                    slot_index counter
#define ST_CAPTURED 0
// Ring Buffer 가 가득 찬 경우 + Slot 이 모두 사용 중인 경우
#define ST_RINGBUF_FULL 1
#define ST_TRUNCATED 2   
#define ST_IP_FRAG_SKIPPED 3
#define ST_ESP_SEEN 4 
#define ST_SLOT_BUSY 5 
#define ST_SLOT_USED_BASE 6
#define ST_COUNT (ST_SLOT_USED_BASE + SLOT_MAX)   

struct cap_event_hdr {
	// bpf_ktime_get_tai_ns
	__u64 capture_tai_ns;   
	__u32 interface_index;
        // addr : network order	
	__u32 src_addr;
	__u32 dst_addr;
	// port : host order
	__u16 src_port; 
	__u16 dst_port;
	__u8  capture_hook;
	__u8  padding0;  
	// EVENT_*
	__u16 flags;  
	__u32 packet_len;
	__u32 captured_len;     
	__u32 padding1;
};

// 커널(bpf)에서 조립한 레코드 (scratch map -> ring buffer)
struct cap_event {
	struct cap_event_hdr hdr;
	// SCTP 공통 헤더(12B)부터 시작
	__u8 sctp_packet[MAX_CAP_BYTES];      
};

_Static_assert(sizeof(struct cap_event_hdr) == 40, "cap_event_hdr 크기가 바뀜: 커널·로더 양쪽 확인");
_Static_assert(__builtin_offsetof(struct cap_event_hdr, capture_hook) == 24, "cap_event_hdr 배치가 바뀜");
_Static_assert(__builtin_offsetof(struct cap_event_hdr, packet_len) == 28, "cap_event_hdr 배치가 바뀜");
_Static_assert(__builtin_offsetof(struct cap_event_hdr, padding1) == 36, "cap_event_hdr 배치가 바뀜");
_Static_assert(__builtin_offsetof(struct cap_event, sctp_packet) == 40, "sctp_packet 은 머리 바로 뒤에서 시작해야 함");

#ifndef __bpf__
#include "cap.h"
_Static_assert(HOOK_TC_INGRESS == CAP_HOOK_TC_INGRESS, "HOOK_TC_INGRESS != CAP_HOOK_TC_INGRESS");
_Static_assert(HOOK_TC_EGRESS == CAP_HOOK_TC_EGRESS, "HOOK_TC_EGRESS != CAP_HOOK_TC_EGRESS");
_Static_assert(SLOT_MAX == CAP_SLOT_MAX, "SLOT_MAX != CAP_SLOT_MAX: cap.h 의 slot_used_count[] 길이도 함께 고칠 것");
#endif

#endif // TELEMETRY_CAP_KERN_ABI_H

