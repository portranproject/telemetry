# PortRAN — 공유 패키지 (팀원용)

**PortRAN** = 5G 분리형 기지국(split-gNB)의 **F1-C 제어평면**을 RAN 무수정·읽기전용 eBPF로 탭해
표준 ASN.1로 디코드하고 per-UE 상태기계로 추적해 **UE 기원 L3 공격을 탐지**하는 수동 보안 센서.

> 처음 보는 분은 **[`ONBOARDING.md`](ONBOARDING.md)** 부터 읽으세요 — 아키텍처·코드 읽는 순서·모듈별 역할이 정리돼 있습니다.
> 각 소스 파일 상단엔 **[신입 가이드] + 함수 지도**, 함수마다 **목적 주석**이 있습니다.

---

## 빠른 시작 (Quickstart)

### 0) 사전 준비
- **빌드**: `clang` `asn1c` `bpftool` `libbpf-dev` `pkg-config` `python3` `make`
- **라이브 실행**: Linux + **root** + `docker`(Open5GS 코어) + **당신의 OCUDU·OAI 빌드**

### 1) 엔진 빌드
```bash
cd ebpf-simple
make                        # 라이브러리(.a) + 단위시험 (첫 빌드는 asn1c 생성 포함, 수 분)
make f1replay detect_engine # 앱: 계측 탭(f1replay) + 탐지엔진(detect_engine) — telemetry.so 링크
make test                   # 자립 검증(커널·root·외부참조 불필요): 단위 + 번들 벡터 디코드 → 17 PASS
# 정리: make clean  /  완전정리: make distclean
```

### 2) 오프라인 실행 (커널·RAN 불필요 — 가장 쉬움)
```bash
./build/f1replay -r testvectors/e2e_nea2_wire.pcap -g 2000
#   → Table II(JSONL, stdout) + Table I/디코드 이벤트(stderr)
```

### 3) 풀스택 라이브 (UE↔OCU↔ODU, root)
당신의 RAN 경로를 지정한 뒤:
```bash
export OCUDU_DIR=~/your/OCUDU  OAI_DIR=~/your/OAI      # ← 당신 환경에 맞게
sudo -E ./testbed/run_e2e_telemetry.sh 20                 # 계측: Table I/II 라이브 수집
sudo -E ATTACK=mal_rrc ./testbed/run_e2e_detect.sh     # 탐지: 공격 참양성(SEM-MALFORMED)
#   → testbed/out/<timestamp>/ 에 telemetry.jsonl·telemetry.err(이벤트)·*.pcap·컴포넌트 로그
```
> 스크립트는 `OCUDU_DIR`/`OAI_DIR` 미지정 시 `~/PortRAN-Project/src/...` 를 기본값으로 쓰고,
> 실행파일이 없으면 안내 메시지와 함께 종료합니다(preflight).

---

## 폴더 구조
| 폴더 | 내용 |
|---|---|
| `ebpf-simple/` | **엔진 소스**(make로 빌드). `src/` 8모듈 · `examples/` 탐지 · `include/telemetry/` 공개 API · `tests/` · `testvectors/` 샘플 pcap |
| `testbed/` | 풀스택(UE↔OCU↔ODU) 실행 스크립트 + 설정(`cu.yml`·`du.yml`·`ue.conf`) |
| `repro/` | 공격 재현 패치(OAI nr-UE 환경변수 공격모드) |
| `eval/` | 라벨 평가 하네스 |
| `dataset/` | 공개 F1-C 코퍼스 |
| `docs/` | 기술 백서(PDF·docx) — 설계·위협모델·검증 전체 |

본 패키지엔 **RAN 스택(OCUDU/OAI/Open5GS)은 포함되지 않습니다** — 당신이 이미 가진 것을 `OCUDU_DIR`/`OAI_DIR` 로 가리키세요.
