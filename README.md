# F1 Test Access Point

F1-C 캡처(eBPF) → F1AP 디코드(asn1c) → 버퍼 출력

```
[커널] f1tap.bpf.c   tcx ingress(DU→CU) + tcx egress(CU→DU)
         IPv4 · SCTP · 포트 38472 패킷의 SCTP 헤더부터 끝 복사
         │ ring buffer
         ▼
[유저] f1tap.c       SCTP 청크 → DATA(PPID 62) → asn1c 디코드(aper_decode_complete) → 출력(xer_fprint)
```

## 코드 구조
| 구분 | 내용 |
|---|---|
| **우리 코드** | `f1tap.bpf.c`(커널 탭 69줄), `f1tap.c`(로더 + SCTP 청크 꺼내기 + 출력 203줄), `f1tap.h` |
| **asn1c** | https://github.com/mouse07410/asn1c @`940dd5fa` (OAI 가 고정해 쓰는 커밋). |
| **F1AP 문법** | 3GPP TS 38.473 V18.8.0 원문(OCUDU 와 같은 판). |

> skb 를 바꾸는 헬퍼(`bpf_skb_pull_data`, `bpf_skb_store_bytes`, `bpf_skb_change_*`, `bpf_skb_adjust_room` 등)를 넣지 말 것.

## 빌드
필요(Ubuntu): `clang llvm bpftool libbpf-dev libelf-dev zlib1g-dev` + asn1c 빌드용 `git autoconf automake libtool bison flex`
```
make -j8         # 처음 한 번: asn1c clone·빌드 → F1AP C 코드 생성(3,616 파일) 및 컴파일
make check-asn1c
make clean       # 생성물 전부 삭제(gen/, build/, 실행 파일 등).
make distclean   # third_party/asn1c 까지 삭제 (다음 make 때 GitHub 에서 다시 받음)
```

## 사용
```
sudo ./f1tap -i <CU 의 F1 쪽 NIC>      # 메시지마다 한 줄 머리 + asn1c XER 전체 디코드 결과
sudo ./f1tap -i <NIC> -t               # asn1c asn_fprint 텍스트 트리 (더 짧음)
sudo ./f1tap -i <NIC> -s               # 한 줄 요약만
sudo ./f1tap -i <NIC> -s -x            # 한 줄 요약 + F1AP 원본 hex (-x 는 다른 옵션과 같이 써도 됨)
```

`RRCContainer` 안의 RRC 메시지는 아직 hex 로만 보인다 (TS 38.331 + asn1c UPER 디코드는 다음 단계).

## vRAN 확인 과정

```
CU(ocu) ═ F1: veth f1cu 192.168.200.1 ↔ netns du f1du 192.168.200.2 ═ DU(odu) ─ZMQ─ OAI UE (netns du)
```

```
# 터미널 1 : CU 시작

# 터미널 2
./f1tap -i f1cu -s -x

```

### 결과

`-s` 로 본 전체 흐름:
```
16:03:55.886473 192.168.200.2:42927 -> 192.168.200.1:38472 DU->CU 182B  F1SetupRequest
16:03:55.886818 192.168.200.1:38472 -> 192.168.200.2:42927 CU->DU 52B  F1SetupResponse
16:03:59.926374 192.168.200.2:42927 -> 192.168.200.1:38472 DU->CU 355B  InitialULRRCMessageTransfer
16:03:59.933371 192.168.200.1:38472 -> 192.168.200.2:42927 CU->DU 334B  DLRRCMessageTransfer
16:04:00.036387 192.168.200.2:42927 -> 192.168.200.1:38472 DU->CU 68B  ULRRCMessageTransfer
16:04:00.072779 192.168.200.1:38472 -> 192.168.200.2:42927 CU->DU 80B  DLRRCMessageTransfer
16:04:00.217594 192.168.200.2:42927 -> 192.168.200.1:38472 DU->CU 59B  ULRRCMessageTransfer
16:04:00.235168 192.168.200.1:38472 -> 192.168.200.2:42927 CU->DU 57B  DLRRCMessageTransfer
16:04:00.313108 192.168.200.2:42927 -> 192.168.200.1:38472 DU->CU 95B  ULRRCMessageTransfer
16:04:00.333184 192.168.200.1:38472 -> 192.168.200.2:42927 CU->DU 56B  UEContextSetupRequest
16:04:00.344941 192.168.200.2:42927 -> 192.168.200.1:38472 DU->CU 330B  UEContextSetupResponse
16:04:00.503785 192.168.200.2:42927 -> 192.168.200.1:38472 DU->CU 37B  ULRRCMessageTransfer
16:04:00.504689 192.168.200.1:38472 -> 192.168.200.2:42927 CU->DU 43B  DLRRCMessageTransfer
16:04:00.589703 192.168.200.2:42927 -> 192.168.200.1:38472 DU->CU 386B  ULRRCMessageTransfer
16:04:00.592303 192.168.200.1:38472 -> 192.168.200.2:42927 CU->DU 96B  DLRRCMessageTransfer
16:04:00.675071 192.168.200.2:42927 -> 192.168.200.1:38472 DU->CU 48B  ULRRCMessageTransfer
16:04:00.716860 192.168.200.1:38472 -> 192.168.200.2:42927 CU->DU 87B  DLRRCMessageTransfer
16:04:00.716884 192.168.200.2:42927 -> 192.168.200.1:38472 DU->CU 75B  ULRRCMessageTransfer
16:04:00.747435 192.168.200.1:38472 -> 192.168.200.2:42927 CU->DU 436B  UEContextModificationRequest
16:04:00.759438 192.168.200.2:42927 -> 192.168.200.1:38472 DU->CU 112B  UEContextModificationResponse
16:04:00.761055 192.168.200.1:38472 -> 192.168.200.2:42927 CU->DU 178B  DLRRCMessageTransfer
16:04:00.876892 192.168.200.2:42927 -> 192.168.200.1:38472 DU->CU 37B  ULRRCMessageTransfer
16:04:08.117462 192.168.200.2:42927 -> 192.168.200.1:38472 DU->CU 62B  ULRRCMessageTransfer
16:04:08.133370 192.168.200.1:38472 -> 192.168.200.2:42927 CU->DU 48B  DLRRCMessageTransfer
16:04:08.340111 192.168.200.1:38472 -> 192.168.200.2:42927 CU->DU 42B  UEContextReleaseCommand
16:04:11.143747 192.168.200.2:42927 -> 192.168.200.1:38472 DU->CU 13B  F1RemovalRequest
16:04:11.144609 192.168.200.1:38472 -> 192.168.200.2:42927 CU->DU 13B  F1RemovalResponse
16:04:11.144633 192.168.200.2:42927 -> 192.168.200.1:38472 DU->CU 19B  UEContextReleaseComplete
```
(F1 Setup → UE 접속: RRC Setup·등록·인증·보안 → UE 컨텍스트 생성 → 베어러 설정 → UE 종료로 해제 → DU 종료로 F1 제거)

`-s -x` (한 줄 요약 + F1AP 원본 hex):
```
16:03:55.886473 192.168.200.2:42927 -> 192.168.200.1:38472 DU->CU 182B  F1SetupRequest
    00 01 00 80 B1 00 00 05 00 4E 00 02 00 00 00 2A
    00 02 00 00 00 2D 40 06 01 80 6F 64 75 30 00 2C
    ...
    8A 00 AB 00 01 10
16:03:55.886818 192.168.200.1:38472 -> 192.168.200.2:42927 CU->DU 52B  F1SetupResponse
    40 01 00 30 00 00 04 00 4E 00 02 00 00 00 52 40
    09 03 00 6F 63 75 63 70 30 31 00 03 00 11 00 00
    00 04 00 0B 40 00 F1 10 00 06 6C 00 00 00 01 00
    AA 00 01 20
```

`-x` (hex + asn1c XER 전체 디코드):
```
16:03:55.886818 192.168.200.1:38472 -> 192.168.200.2:42927 CU->DU 52B  F1SetupResponse
    40 01 00 30 00 00 04 00 4E 00 02 00 00 00 52 40
    09 03 00 6F 63 75 63 70 30 31 00 03 00 11 00 00
    00 04 00 0B 40 00 F1 10 00 06 6C 00 00 00 01 00
    AA 00 01 20
<F1AP-PDU>
    <successfulOutcome>
        <procedureCode>1</procedureCode>
        <criticality><reject/></criticality>
        <value>
            <F1SetupResponse>
                <protocolIEs>
                    <F1SetupResponseIEs>
                        <id>78</id>
                        <criticality><reject/></criticality>
                        <value>
                            <TransactionID>0</TransactionID>
                        </value>
                    </F1SetupResponseIEs>
                    <F1SetupResponseIEs>
                        <id>82</id>
                        <criticality><ignore/></criticality>
                        <value>
                            <GNB-CU-Name>ocucp01</GNB-CU-Name>
                        </value>
                    </F1SetupResponseIEs>
                    <F1SetupResponseIEs>
                        <id>3</id>
                        <criticality><reject/></criticality>
                        <value>
                            <Cells-to-be-Activated-List>
                                <ProtocolIE-SingleContainer>
                                    <id>4</id>
                                    <criticality><reject/></criticality>
                                    <value>
                                        <Cells-to-be-Activated-List-Item>
                                            <nRCGI>
                                                <pLMN-Identity>00 F1 10</pLMN-Identity>
                                                <nRCellIdentity>
                                                    000000000000011001101100000000000000
                                                </nRCellIdentity>
                                            </nRCGI>
                                            <nRPCI>1</nRPCI>
                                        </Cells-to-be-Activated-List-Item>
                                    </value>
                                </ProtocolIE-SingleContainer>
                            </Cells-to-be-Activated-List>
                        </value>
                    </F1SetupResponseIEs>
                    <F1SetupResponseIEs>
                        <id>170</id>
                        <criticality><reject/></criticality>
                        <value>
                            <RRC-Version>
                                <latest-RRC-Version>
                                    010
                                </latest-RRC-Version>
                            </RRC-Version>
                        </value>
                    </F1SetupResponseIEs>
                </protocolIEs>
            </F1SetupResponse>
        </value>
    </successfulOutcome>
</F1AP-PDU>
```
