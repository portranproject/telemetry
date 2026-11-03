#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "cap_kern_abi.h"

struct slot {
	__u32 busy;
	__u32 padding;
	struct cap_event kern_event;
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

// bump: stats 의 stat_index(ST_*) 칸에 +1
static __always_inline void bump(__u32 stat_index) {
	__u64 *counter = bpf_map_lookup_elem(&stats, &stat_index);
	if (counter)
		__sync_fetch_and_add(counter, 1);
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
	__u32 base = (bpf_get_smp_processor_id() * HOOK_COUNT + capture_hook) * slot_count;
	for (__u32 slot_index = 0; slot_index < SLOT_MAX; slot_index++) { 
		if (slot_index >= slot_count)
			break;
		__u32 slot_key = base + slot_index;
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

