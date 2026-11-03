/**
 * cap_kern_abi.h 
 * : libcap 비공개 헤더 파일, 커널(cap.bpf.c) <-> 로더(cap.c) 간 데이터 전달 형식 정의
 */

#ifndef TELEMETRY_CAP_KERN_ABI_H
#define TELEMETRY_CAP_KERN_ABI_H

#include <linux/types.h>

// sctp_packet[] 상한
#define MAX_CAP_BYTES 65536 

#define HOOK_TC_INGRESS 0
#define HOOK_TC_EGRESS 1
#define HOOK_COUNT 2

// (CPU, HOOK) 이 동시에 점유할 수 있는 slot 수 = 
// 	PREEMPT_RT nesting 깊이 상한 (보통 커널은 1칸)
#define SLOT_MAX 4

// cap_event_hdr.flags (captured_len < packet_len)
#define EVENT_TRUNCATED 0x1

#endif // TELEMETRY_CAP_KERN_ABI_H

