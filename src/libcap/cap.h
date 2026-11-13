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
	// SCTP 공통 헤더(12B)부터 시작하는 패킷 바이트
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
	uint64_t captured_count;          
	uint64_t ringbuf_full_count;
	uint64_t truncated_count;
	uint64_t ip_frag_skipped_count;
	// IPsec(ESP) 패킷	
	uint64_t esp_seen_count;
	
	// slot_busy_count : PREEMPT_RT 재진입이 CAP_SLOT_MAX 보다 깊은 경우
	// ringbuf_full_count - slot_busy_count : consumer 처리가 늦은 경우
	uint64_t slot_busy_count;
	
	// slot_used_count[1~] != 0 : nesting 을 다른 slot 으로 해결한 것
	// (단, slot 이 다 차면 slot_busy_count)
	uint64_t slot_used_count[CAP_SLOT_MAX];
};

/* 인터페이스 하나의 한 방향 와이어 계수기. 프로그램이 도는 동안 계속 커지므로, 구간 값은
 *   호출자가 두 번 읽어 차이를 냄. 차이를 내려면 앞선 성공값이 있어야 하므로 첫 구간은 값이 없음 */
struct cap_link_direction_stats {
	// 와이어 SCTP 패킷 수. GSO 로 묶인 skb 하나는 그 안의 세그먼트 수만큼 셈
	uint64_t sctp_packet_count;
	// 와이어 바이트. 이더넷 헤더 포함, FCS 제외
	uint64_t wire_byte_count;
};

struct cap_link_stats {
	// DU -> CU
	struct cap_link_direction_stats ingress;
	// CU -> DU
	struct cap_link_direction_stats egress;
};

struct cap;

typedef void (*cap_record_cb)(void *user_ctx, const struct cap_record *record);

int cap_open(const struct cap_interface *interfaces, int interface_count, struct cap **cap_out);
int cap_poll(struct cap *cap, int timeout_ms, cap_record_cb record_cb, void *user_ctx);
void cap_detach(struct cap *cap);
int cap_get_stats(const struct cap *cap, struct cap_stats *stats_out);
int cap_get_link_stats(const struct cap *cap, struct cap_link_stats *stats_out, int stats_capacity);
enum cap_interface_role cap_get_interface_role(const struct cap *cap, uint32_t interface_index);
void cap_close(struct cap *cap);

#endif // TELEMETRY_CAP_H

