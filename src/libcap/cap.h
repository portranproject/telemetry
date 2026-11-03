#ifndef TELEMETRY_CAP_H
#define TELEMETRY_CAP_H

#include <stdint.h>

enum cap_hook {
       	// tcx ingress: DU -> CU
	CAP_HOOK_TC_INGRESS = 0,   
	// tcx egress: CU -> DU
	CAP_HOOK_TC_EGRESS  = 1  
};

struct cap_record {
	uint64_t capture_time_ns;
	uint32_t interface_index;
	enum cap_hook capture_hook;
	// addr -> network order
	uint32_t src_addr; 
	uint32_t dst_addr;
	// port -> host order
	uint16_t src_port;
	uint16_t dst_port;
	// SCTP 공통 헤더(12B)부터 시작하는 패킷 바이트.
	const uint8_t *sctp_packet; 
	uint32_t captured_len;      
	uint32_t packet_len;        
};

enum cap_interface_role {
	CAP_ROLE_UNKNOWN = 0,
	CAP_ROLE_F1 = 1,
	CAP_ROLE_N2 = 2             
};

struct cap_interface {
	const char *interface_name;
	enum cap_interface_role role;
};

#define CAP_SLOT_MAX 4
struct cap_stats {
	uint64_t captured;          
	uint64_t ringbuf_full;
	uint64_t truncated;
	uint64_t ip_frag_skipped;
	// IPsec(ESP) 패킷	
	uint64_t esp_seen;
	
	// slot_busy : PREEMPT_RT 재진입이 CAP_SLOT_MAX 보다 깊은 경우
	// ringbuf_full - slot_busy : consumer 처리가 늦은 경우
	uint64_t slot_busy;
	
	// slot_used[1~] != 0 : nesting 을 다른 slot 으로 해결한 것
	// (단, slot 이 다 차면 slot_busy)
	uint64_t slot_used[CAP_SLOT_MAX];
};

#endif // TELEMETRY_CAP_H

