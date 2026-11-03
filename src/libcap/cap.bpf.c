#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include "cap_kern_abi.h"

struct slot {
	__u32 busy;
	__u32 padding;
	struct cap_event kern_event;
};

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


