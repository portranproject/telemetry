// f1tap.bpf.c : F1-C(SCTP 38472) 패킷을 그대로 복사해 ring buffer 로 전달함.
//   [1] tcx ingress + tcx egress
//   [2] 매칭되면 SCTP 공통헤더부터 끝까지 복사만 진행

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "f1tap.h"

#define TCX_NEXT -1

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 25);   // 32 MiB
} rb SEC(".maps");

static __always_inline void tap(struct __sk_buff *skb, __u8 egress)
{
    struct ethhdr eth;
    struct iphdr ip;
    if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth))) return;
    if (eth.h_proto != bpf_htons(ETH_P_IP)) return; // IPv4 만
    if (bpf_skb_load_bytes(skb, sizeof(eth), &ip, sizeof(ip))) return;
    if (ip.protocol != IPPROTO_SCTP) return;
    if (ip.frag_off & bpf_htons(0x3FFF)) return; // IP 단편은 건너뜀

    if (ip.ihl < 5) return;
    __u32 off = sizeof(eth) + ip.ihl * 4; // SCTP 공통헤더 위치
    __be16 port[2];
    if (bpf_skb_load_bytes(skb, off, port, sizeof(port))) return;
    if (port[0] != bpf_htons(F1AP_PORT) && port[1] != bpf_htons(F1AP_PORT)) return;
    if (skb->len <= off) return;

    struct f1_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return; // 버퍼가 가득 → 이 패킷은 놓침

    // 복사 길이는 마지막 헬퍼 호출 뒤에 계산(Verifier)
    __u32 len = skb->len - off;
    if (len > MAX_CAP - 1) len = MAX_CAP - 1;
    barrier_var(len); // clang 이 아래 마스크를 지우지 못하게 (Verifier)
    len &= MAX_CAP - 1;
    if (len == 0 || bpf_skb_load_bytes(skb, off, e->data, len)) {
        bpf_ringbuf_discard(e, 0);
        return;
    }
    e->ts_ns  = bpf_ktime_get_tai_ns();
    e->saddr  = ip.saddr;
    e->daddr  = ip.daddr;
    e->len    = len;
    e->egress = egress;
    bpf_ringbuf_submit(e, 0);
}

SEC("tcx/ingress")
int f1tap_ingress(struct __sk_buff *skb) {
    tap(skb, 0);
    return TCX_NEXT;
}

SEC("tcx/egress")
int f1tap_egress(struct __sk_buff *skb) {
    tap(skb, 1);
    return TCX_NEXT;
}

char LICENSE[] SEC("license") = "GPL";
