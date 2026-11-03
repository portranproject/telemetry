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

#endif // TELEMETRY_CAP_H

