// f1tap.h : 커널(f1tap.bpf.c) ↔ 유저(f1tap.c) 공유 이벤트 구조
#ifndef F1TAP_H
#define F1TAP_H

#define F1AP_PORT 38472   // F1-C SCTP 포트 (TS 38.472)
#define MAX_CAP   65536   // SCTP 헤더부터 복사하는 최대 바이트 (lo MTU 65536, egress GSO 묶음 ≤ 64KB)

struct f1_event {
    __u64 ts_ns;      // bpf_ktime_get_tai_ns (CLOCK_TAI)
    __u32 saddr;      // IPv4 src (network order)
    __u32 daddr;      // IPv4 dst (network order)
    __u32 len;        // data[] 에 담긴 바이트 수 (SCTP 공통헤더 + 청크들)
    __u8  egress;     // 0 = tcx ingress, 1 = tcx egress
    __u8  pad[3];
    __u8  data[MAX_CAP];
};

#endif
