/**
 * cap.bpf.c 
 * : 패킷 추출 및 레코드 조립
 *
 * capture_tc_ingress (DU->CU)        capture_tc_egress (CU->DU)
 *          |                                    |
 *          +-----------------+------------------+
 *                            |
 *                          tap()
 *                            |
 *  +---- 1. L2: Ethernet 헤더 + 인라인 VLAN 태그 건너뛰기
 *  |
 *  +---- 2. IPv4 && SCTP
 *  |         ESP                -> ST_ESP_SEEN
 *  |         IP Frag            -> ST_IP_FRAG_SKIPPED (재조립 x)
 *  |         포트 읽기 실패     -> ST_TRUNCATED
 *  |
 *  +---- 3. slot_get
 *            |   scratch[(cpu * HOOK_COUNT + hook) * slot_count + i],  i < slot_count
 *            |   slot 획득 실패 -> ST_SLOT_BUSY + ST_RINGBUF_FULL
 *            |   slot 점유      -> ST_SLOT_USED_BASE + i
 *            |
 *            +-- emit(slot->kernel_event)
 *            |   복사 실패      -> ST_TRUNCATED
 *            |   버퍼 한계      -> ST_RINGBUF_FULL
 *            |   성공           -> ST_CAPTURED (+ 잘렸으면 ST_TRUNCATED)
 *            |
 *            +-- slot_put()
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "cap_kern_abi.h"

// IPv4 More Fragments
#define IP_MF     0x2000 
#define IP_OFFSET 0x1FFF

#define SCTP_COMMON_HEADER_BYTES 12
#define VLAN_MAX_TAGS 2

// 802.1Q/802.1ad VLAN 태그 (4B). h_proto 가 0x8100/0x88A8 인 경우
struct vlan_tag {
	__be16 tci;
	__be16 inner_ether_type;
};

struct slot {
	__u32 busy;
	__u32 padding;
	struct cap_event kernel_event;
};

const volatile __u32 slot_count = 1;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 27);
} ringbuf SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, HOOK_COUNT);
	__type(key, __u32);
	__type(value, struct slot);
} scratch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, ST_COUNT);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

// 인터페이스와 방향별 와이어 계수기. 칸 수는 로더가 interface_count x HOOK_COUNT 로 늘림(scratch 와 같은 방식)
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, HOOK_COUNT);
	__type(key, __u32);
	__type(value, struct link_counter);
} link_stats SEC(".maps");

// load : offset_bytes ~ +len 구간에 걸친 skb 조각(선형 헤더/frags[]/frag_list)를 순서대로 dst 로 복사
//
//     0       14      34                                      60000
//     +-------+-------+----------+----------+----------+-------------+
//     | Eth   | IP    | SCTP header | chunks 1 | chunks 2 | chunks 3 |
//     +-------+-------+----------+----------+----------+-------------+
//     |<----------- linear head ----------->|<---- frag_list ------->|
//                     |<------- load(skb, 34, dst, 59966) ---------->|
//                                     |
//                                     v
//     +----------+----------+----------+-------------+
//     | SCTP header | chunks 1 | chunks 2 | chunks 3 |
//     +----------+----------+----------+-------------+
static __always_inline long load(struct __sk_buff *skb, __u32 offset_bytes, void *dst, __u32 len) {
	return bpf_skb_load_bytes(skb, offset_bytes, dst, len);
}

// bump: stats 의 stat_index(ST_*) 칸에 +1
static __always_inline void bump(__u32 stat_index) {
	__u64 *counter = bpf_map_lookup_elem(&stats, &stat_index);
	if (counter)
		__sync_fetch_and_add(counter, 1);
}

// count_link: 이 패킷을 인터페이스와 방향별 계수기에 더함.
// 	SCTP 필터를 통과한 뒤에만 부름. 그 앞에서 부르면 세는 단위가 L2 프레임이 되어 이름이 거짓이 되고,
// 		SCTP 가 아닌 프레임(SSH, ARP)까지 맵 조회 비용을 지불함.
// 	slot_get 보다 앞에서 부르는 이유: 칸이 모자라거나 링 버퍼가 차서 버린 패킷도 와이어에는 있었으므로
// 		세어야 함. 뒤에 두면 과부하에서 측정값이 과소 계상됨
static __always_inline void count_link(struct __sk_buff *skb, __u8 capture_hook, __u32 interface_index, __u32 frame_len) {
	__u32 link_key = interface_index * HOOK_COUNT + capture_hook;
	struct link_counter *counter = bpf_map_lookup_elem(&link_stats, &link_key);
	// 칸이 없음 = 로더가 넣지 않은 인터페이스. 지어내지 않고 세지 않음
	if (!counter)
		return;
	// gso_segs 0: GSO 로 묶이지 않은 보통 skb. wire_len 0: 이 훅에서 커널이 채우지 않은 경우
	__u32 segment_count = skb->gso_segs ? skb->gso_segs : 1;
	__u32 wire_len = skb->wire_len ? skb->wire_len : frame_len;
	__sync_fetch_and_add(&counter->sctp_packet_count, segment_count);
	__sync_fetch_and_add(&counter->wire_byte_count, wire_len);
}

// slot_get: 현재 CPU 및 훅(ingress/egress)의 빈 slot 반환
//   scratch map key = (cpu * HOOK_COUNT + capture_hook) * slot_count + slot_index
//   case)
//     slot_count = 1
//       group:  cpu0/in | cpu0/eg | cpu1/in | cpu1/eg
//       key:       0    |    1    |    2    |    3
//
//     slot_count = SLOT_MAX = 4 (PREEMPT_RT)
//       group:        cpu0/in   |   cpu0/eg   |   cpu1/in   |   cpu1/eg
//       key:         0  1  2  3 |  4  5  6  7 |  8  9 10 11 | 12 13 14 15
//       slot_index:  0  1  2  3 |  0  1  2  3 |  0  1  2  3 |  0  1  2  3
static __always_inline struct slot *slot_get(__u8 capture_hook) {
	__u32 slot_base_index = (bpf_get_smp_processor_id() * HOOK_COUNT + capture_hook) * slot_count;
	for (__u32 slot_index = 0; slot_index < SLOT_MAX; slot_index++) { 
		if (slot_index >= slot_count)
			break;
		__u32 slot_key = slot_base_index + slot_index;
		struct slot *slot = bpf_map_lookup_elem(&scratch, &slot_key);
		if (slot && __sync_val_compare_and_swap(&slot->busy, 0, 1) == 0) {
			bump(ST_SLOT_USED_BASE + slot_index);
			return slot;
		}
	}
	return NULL;
}

static __always_inline void slot_put(struct slot *slot) {
	__sync_lock_test_and_set(&slot->busy, 0);
}

struct parsed_pkt {
	__u32 interface_index;
	__u32 src_addr;
	__u32 dst_addr;
	__u32 sctp_offset_bytes;
	__u32 packet_len;
	__u16 src_port;
	__u16 dst_port;
	__u8  capture_hook;
};

// emit: 획득한 slot 의 kernel_event 에 레코드를 채워 Ring Buffer 로 전송
static __always_inline void emit(struct __sk_buff *skb, struct cap_event *kernel_event, const struct parsed_pkt *pkt) {
	kernel_event->header.capture_tai_ns = bpf_ktime_get_tai_ns();     

	kernel_event->header.interface_index = pkt->interface_index;
	kernel_event->header.src_addr = pkt->src_addr;
	kernel_event->header.dst_addr = pkt->dst_addr;
	kernel_event->header.src_port = pkt->src_port;
	kernel_event->header.dst_port = pkt->dst_port;
	kernel_event->header.packet_len = pkt->packet_len;
	kernel_event->header.capture_hook = pkt->capture_hook;
	kernel_event->header.padding0 = 0;
	kernel_event->header.padding1 = 0;

	__u32 captured_len = pkt->packet_len;
	if (captured_len > MAX_CAP_BYTES - 1)
		captured_len = MAX_CAP_BYTES - 1;
	barrier_var(captured_len);
	captured_len = ((captured_len - 1) & (MAX_CAP_BYTES - 1)) + 1;
	
	kernel_event->header.captured_len = captured_len;
	kernel_event->header.flags = captured_len < pkt->packet_len ? EVENT_TRUNCATED : 0;

	if (load(skb, pkt->sctp_offset_bytes, kernel_event->sctp_packet, captured_len)) {  
		// ip_header.tot_len 이 실제 패킷보다 길게 적힌 깨진 패킷
		bump(ST_TRUNCATED);
		return;
	}
	// map 에서 다시 읽은 값은 verifier 가 범위 모름. 같은 마스크로 상한을 다시 증명
	__u32 captured_len_from_map = ((kernel_event->header.captured_len - 1) & (MAX_CAP_BYTES - 1)) + 1;
	if (bpf_ringbuf_output(&ringbuf, kernel_event, sizeof(struct cap_event_header) + captured_len_from_map, 0)) {
		bump(ST_RINGBUF_FULL); 
		return;
	}
	bump(ST_CAPTURED);
	if (kernel_event->header.flags & EVENT_TRUNCATED)
		bump(ST_TRUNCATED);
}

// tap: 패킷 하나 처리 : 헤더 검사 -> slot 획득 -> 레코드 생성 후 Ring Buffer 로 전달 -> slot 반환
//   capture_hook : HOOK_TC_INGRESS / HOOK_TC_EGRESS
//   frame_len : skb->len. tc 기준 이더넷을 포함한 프레임 전체 길이
//   interface_index : 인터페이스 번호
static __always_inline void tap(struct __sk_buff *skb, const __u8 capture_hook, __u32 frame_len, __u32 interface_index) {
	struct ethhdr eth_header;
	if (load(skb, 0, &eth_header, sizeof(eth_header)))
		return;
	__be16 ether_type = eth_header.h_proto; 
	__u32 l2_len = sizeof(eth_header); 

	// 인라인 VLAN 태그(802.1Q/Q-in-Q) 최대 VLAN_MAX_TAGS 검사
	for (int i = 0; i < VLAN_MAX_TAGS; i++) {
		if (ether_type != bpf_htons(ETH_P_8021Q) && ether_type != bpf_htons(ETH_P_8021AD))
			break;
		struct vlan_tag vlan_tag;
		if (load(skb, l2_len, &vlan_tag, sizeof(vlan_tag)))
			return;
		ether_type = vlan_tag.inner_ether_type;
		l2_len += sizeof(vlan_tag);
	}

	if (ether_type != bpf_htons(ETH_P_IP)) 
		return;
	struct iphdr ip_header;
	if (load(skb, l2_len, &ip_header, sizeof(ip_header)))
		return;
	if (ip_header.version != 4)
		return; 
	if (ip_header.protocol == IPPROTO_ESP) {
		bump(ST_ESP_SEEN);
		return;
	}
	if (ip_header.protocol != IPPROTO_SCTP)
		return;
	if (ip_header.frag_off & bpf_htons(IP_MF | IP_OFFSET)) {
		bump(ST_IP_FRAG_SKIPPED); 
		return;
	}
	__u32 ip_header_len = (__u32)ip_header.ihl * 4;
	if (ip_header_len < sizeof(struct iphdr)) 
		return;
	if (frame_len < l2_len + ip_header_len) 
		return;
       
	// SCTP Common Header 시작 위치	
	__u32 sctp_offset_bytes = l2_len + ip_header_len;
	// SCTP packet_len 결정(하드닝)
	//   - skb_ip_len ≤ 65535: ip_header.tot_len 활용
	//   - skb_ip_len > 65535: ip_header.tot_len 으로 나타낼 수 없는 길이 = GSO 로 묶인 큰 skb. 
	//   	-> skb 길이 활용
	__u32 skb_ip_len = frame_len - l2_len;
	__u32 ip_total_len = bpf_ntohs(ip_header.tot_len);
	__u32 packet_len;
	if (skb_ip_len > 0xFFFF) {
		packet_len = skb_ip_len - ip_header_len;
	} else {
		if (ip_total_len <= ip_header_len)
			return;
		packet_len = ip_total_len - ip_header_len;
	}
	if (packet_len < SCTP_COMMON_HEADER_BYTES)
		return; 

	count_link(skb, capture_hook, interface_index, frame_len);

	__be16 ports[2];
	if (load(skb, sctp_offset_bytes, ports, sizeof(ports))) {
		bump(ST_TRUNCATED);
		return;
	}
	// network order -> host order
	__u16 src_port = bpf_ntohs(ports[0]);
	__u16 dst_port = bpf_ntohs(ports[1]);

	struct slot *slot = slot_get(capture_hook);
	if (!slot) { 
		bump(ST_SLOT_BUSY);
		bump(ST_RINGBUF_FULL);
		return; 
	}
	struct parsed_pkt pkt = {
		.interface_index = interface_index, .src_addr = ip_header.saddr, .dst_addr = ip_header.daddr,
		.sctp_offset_bytes = sctp_offset_bytes, .packet_len = packet_len, .src_port = src_port, .dst_port = dst_port, .capture_hook = capture_hook,
	};
	emit(skb, &slot->kernel_event, &pkt);
	slot_put(slot);
}

SEC("tcx/ingress")
int capture_tc_ingress(struct __sk_buff *skb) {
	tap(skb, HOOK_TC_INGRESS, skb->len, skb->ifindex);
	return TCX_NEXT;
}

SEC("tcx/egress")
int capture_tc_egress(struct __sk_buff *skb) {
	tap(skb, HOOK_TC_EGRESS, skb->len, skb->ifindex);
	return TCX_NEXT;
}

char LICENSE[] SEC("license") = "GPL";

