// f1tap.c : 로더 + ring buffer consumer
//   커널(f1tap.bpf.c)이 넘긴 SCTP 패킷 → DATA 청크(PPID 62 = F1AP) 꺼내기 → asn1c APER 디코드 → 출력
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include "f1tap.h"
#include "f1tap.skel.h"

#include <F1AP_F1AP-PDU.h>             // asn1c 생성 (gen/)
#include <F1AP_InitiatingMessage.h>
#include <F1AP_SuccessfulOutcome.h>
#include <F1AP_UnsuccessfulOutcome.h>

#define PPID_F1AP 62   // TS 38.472 §7

static volatile sig_atomic_t stop;
static int opt_text, opt_summary, opt_hex;
static int64_t tai2real_ns;            // CLOCK_REALTIME - CLOCK_TAI
static unsigned long n_pkt, n_msg, n_fail, n_dup;

static void on_sig(int s) { (void)s; stop = 1; }
static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static uint32_t rd32(const uint8_t *p) { return (uint32_t)p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3]; }

// ---------------- SCTP (RFC 9260) ----------------
// 한 방향(src→dst) 흐름마다: 마지막 TSN(중복 제거) + 조각(fragment) 재조립 버퍼.
//  중복이 생기는 경우: lo 는 같은 패킷이 egress 와 ingress 를 둘 다 지나감, 재전송.
struct flow {
    uint32_t saddr, daddr, vtag, last_tsn, frag_next;
    uint16_t sport, dport;
    int used, seen, frag_on;
    uint8_t *frag;
    size_t frag_len;
};
static struct flow flows[16];

static struct flow *flow_get(uint32_t sa, uint32_t da, uint16_t sp, uint16_t dp, uint32_t vtag)
{
    struct flow *f = NULL;
    for (int i = 0; i < 16 && !f; i++)
        if (flows[i].used && flows[i].saddr == sa && flows[i].daddr == da &&
            flows[i].sport == sp && flows[i].dport == dp) f = &flows[i];
    for (int i = 0; i < 16 && !f; i++)
        if (!flows[i].used) f = &flows[i];
    if (!f) f = &flows[0]; // 표가 가득: 첫 칸 재사용
    if (!f->used || f->vtag != vtag || f->saddr != sa || f->daddr != da || f->sport != sp || f->dport != dp) {
        free(f->frag); // 새 연결(vtag 변경) → 상태 초기화
        *f = (struct flow){ .saddr = sa, .daddr = da, .sport = sp, .dport = dp, .vtag = vtag, .used = 1 };
    }
    return f;
}

// ---------------- F1AP (asn1c) ----------------
// 메시지 이름 = PDU → initiating/successful/unsuccessful → value(open type CHOICE) 에서 고른 멤버 이름
static const char *msg_name(const F1AP_F1AP_PDU_t *pdu)
{
    const asn_TYPE_descriptor_t *td;
    const void *msg;
    switch (pdu->present) {
    case F1AP_F1AP_PDU_PR_initiatingMessage:   td = &asn_DEF_F1AP_InitiatingMessage;   msg = pdu->choice.initiatingMessage;   break;
    case F1AP_F1AP_PDU_PR_successfulOutcome:   td = &asn_DEF_F1AP_SuccessfulOutcome;   msg = pdu->choice.successfulOutcome;   break;
    case F1AP_F1AP_PDU_PR_unsuccessfulOutcome: td = &asn_DEF_F1AP_UnsuccessfulOutcome; msg = pdu->choice.unsuccessfulOutcome; break;
    default: return "?";
    }
    const asn_TYPE_member_t *val = &td->elements[2];        // procedureCode, criticality, value
    unsigned pres = CHOICE_variant_get_presence(val->type, (const char *)msg + val->memb_offset);
    return pres ? val->type->elements[pres - 1].name : "?";
}

// F1AP PDU 원본 바이트를 16바이트씩 hex 로
static void hexdump(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
        printf("%s%02X%s", i % 16 ? "" : "    ", p[i], (i % 16 == 15 || i + 1 == n) ? "\n" : " ");
}

static void on_f1ap(const struct f1_event *e, uint16_t sp, uint16_t dp, const uint8_t *buf, size_t len)
{
    n_msg++;
    // 시각 + 방향
    uint64_t ns = (uint64_t)((int64_t)e->ts_ns + tai2real_ns);
    time_t sec = (time_t)(ns / 1000000000ull);
    struct tm tm;
    localtime_r(&sec, &tm);
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &e->saddr, src, sizeof(src));
    inet_ntop(AF_INET, &e->daddr, dst, sizeof(dst));
    const char *dir = dp == F1AP_PORT && sp != F1AP_PORT ? "DU->CU" : sp == F1AP_PORT && dp != F1AP_PORT ? "CU->DU" : "";

    F1AP_F1AP_PDU_t *pdu = NULL;
    asn_dec_rval_t rv = aper_decode_complete(NULL, &asn_DEF_F1AP_F1AP_PDU, (void **)&pdu, buf, len);
    int ok = rv.code == RC_OK;
    if (!ok) n_fail++;

    printf("%02d:%02d:%02d.%06lu %s:%u -> %s:%u %s %zuB  %s\n", tm.tm_hour, tm.tm_min, tm.tm_sec,
           (unsigned long)(ns % 1000000000ull / 1000), src, sp, dst, dp, dir, len,
           ok ? msg_name(pdu) : "** APER 디코드 실패 **");
    if (opt_hex || !ok) hexdump(buf, len);              // 디코드 실패면 항상 hex
    if (ok && !opt_summary) {
        if (opt_text) asn_fprint(stdout, &asn_DEF_F1AP_F1AP_PDU, pdu);
        else xer_fprint(stdout, &asn_DEF_F1AP_F1AP_PDU, pdu);
        printf("\n");
    }
    ASN_STRUCT_FREE(asn_DEF_F1AP_F1AP_PDU, pdu);
}

// DATA 청크 하나: 조각이 아니면 바로 디코드, 조각이면 B(첫)~E(끝)를 이어 붙인 뒤 디코드
static void on_data(const struct f1_event *e, struct flow *f, uint8_t flags, uint32_t tsn,
                    const uint8_t *p, size_t n)
{
    const int B = 0x02, E = 0x01;
    if ((flags & (B | E)) == (B | E)) { on_f1ap(e, f->sport, f->dport, p, n); return; }
    if (flags & B) { f->frag_on = 1; f->frag_len = 0; }
    else if (!f->frag_on || tsn != f->frag_next) { f->frag_on = 0; return; }   // 앞 조각을 놓침 → 버림
    uint8_t *nb = realloc(f->frag, f->frag_len + n);
    if (!nb) { f->frag_on = 0; return; }
    f->frag = nb;
    memcpy(f->frag + f->frag_len, p, n);
    f->frag_len += n;
    f->frag_next = tsn + 1;
    if (flags & E) { f->frag_on = 0; on_f1ap(e, f->sport, f->dport, f->frag, f->frag_len); }
}

static int on_event(void *ctx, void *data, size_t size)
{
    const struct f1_event *e = data;
    const uint8_t *p = e->data;
    size_t n = e->len;
    n_pkt++;
    if (n < 12) return 0;
    // SCTP 공통헤더: src port, dst port, verification tag, checksum
    struct flow *f = flow_get(e->saddr, e->daddr, rd16(p), rd16(p + 2), rd32(p + 4));
    // 청크: type(1) flags(1) length(2) value… (4바이트 경계로 패딩). egress GSO 묶음이면 여러 세그먼트의 청크가 이어져 있다.
    for (size_t off = 12; off + 4 <= n;) {
        uint8_t type = p[off], flags = p[off + 1];
        size_t clen = rd16(p + off + 2);
        if (clen < 4 || off + clen > n) break;
        if (type == 0 && clen > 16) {                       // DATA: TSN(4) SID(2) SSN(2) PPID(4) + 사용자 데이터
            uint32_t tsn = rd32(p + off + 4), ppid = rd32(p + off + 12);
            if (f->seen && (int32_t)(tsn - f->last_tsn) <= 0) n_dup++;      // 이미 본 TSN
            else {
                f->seen = 1;
                f->last_tsn = tsn;
                if (ppid == PPID_F1AP) on_data(e, f, flags, tsn, p + off + 16, clen - 16);
            }
        }
        off += (clen + 3) & ~(size_t)3;
    }
    return 0;
}

int main(int argc, char **argv)
{
    const char *ifname = NULL;
    int o;
    while ((o = getopt(argc, argv, "i:tsx")) != -1) {
        if (o == 'i') ifname = optarg;
        else if (o == 't') opt_text = 1;
        else if (o == 's') opt_summary = 1;
        else if (o == 'x') opt_hex = 1;
        else { ifname = NULL; break; }
    }
    if (!ifname) {
        fprintf(stderr, "usage: %s -i <ifname> [-t] [-s] [-x]\n"
                        "  -i IF  탭을 붙일 인터페이스 (CU 의 F1 쪽 NIC)\n"
                        "  (기본) asn1c XER(XML) 로 전체 디코드 결과 출력\n"
                        "  -t     asn1c asn_fprint 텍스트 트리로 출력 (더 짧음)\n"
                        "  -s     메시지마다 한 줄 요약만 출력\n"
                        "  -x     F1AP PDU 원본 바이트도 hex 로 출력 (-s 와 같이 쓸 수 있음)\n", argv[0]);
        return 1;
    }
    unsigned ifindex = if_nametoindex(ifname);
    if (!ifindex) { perror(ifname); return 1; }

    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);
    struct timespec t, r;
    clock_gettime(CLOCK_TAI, &t);
    clock_gettime(CLOCK_REALTIME, &r);
    tai2real_ns = (int64_t)(r.tv_sec - t.tv_sec) * 1000000000LL + (r.tv_nsec - t.tv_nsec);

    int ret = 1;
    struct bpf_link *l_in = NULL, *l_eg = NULL;
    struct ring_buffer *rb = NULL;
    struct f1tap_bpf *skel = f1tap_bpf__open_and_load();
    if (!skel) { fprintf(stderr, "BPF 로드 실패\n"); goto out; }
    // tcx 체인 맨 앞에 붙는다(다른 프로그램이 드롭/리다이렉트하기 전을 본다). 프로세스가 끝나면 자동 해제.
    LIBBPF_OPTS(bpf_tcx_opts, first, .flags = BPF_F_BEFORE);
    l_in = bpf_program__attach_tcx(skel->progs.f1tap_ingress, (int)ifindex, &first);
    l_eg = bpf_program__attach_tcx(skel->progs.f1tap_egress, (int)ifindex, &first);
    if (!l_in || !l_eg) { fprintf(stderr, "tcx attach 실패\n"); goto out; }
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), on_event, NULL, NULL);
    if (!rb) { fprintf(stderr, "ring buffer 실패\n"); goto out; }

    fprintf(stderr, "[f1tap] %s 에서 F1AP(SCTP %d) 캡처 중… Ctrl+C 로 종료\n", ifname, F1AP_PORT);
    while (!stop) ring_buffer__poll(rb, 200);
    ring_buffer__consume(rb);
    ret = 0;
out:
    fprintf(stderr, "[f1tap] packets=%lu f1ap=%lu decode_fail=%lu dup_tsn=%lu\n", n_pkt, n_msg, n_fail, n_dup);
    ring_buffer__free(rb);
    bpf_link__destroy(l_in);
    bpf_link__destroy(l_eg);
    f1tap_bpf__destroy(skel);
    return ret;
}
