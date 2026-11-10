# PortRAN 계측 엔진. 배포물은 build/portran-telemetry.so(전 모듈 한 덩어리)와 build/portran
#
# 파이프라인. 각 폴더가 lib<모듈>.a 가 되고 그것들을 한 .so 로 묶음:
#
#   libcap  --> libsctp  --> libap    --> libobs --> libtelemetry --> libsink
#   (캡처)      (재조립)     librrc       (관측      (표 I/II 집계)    (출력)
#                            libnas       이벤트)
#                            (디코드)
#
#   빈 폴더는 $(wildcard) 로 자동 제외되므로 일부만 있어도 빌드됨
#
#   make                    build/libcap.a + build/portran + build/portran-telemetry.so
#   make portran            파이프라인 실행 파일만
#   make portran-telemetry  배포물 .so 만
#   make asn1               asn1c 를 고정 커밋에서 받아 빌드하고 F1AP/NGAP/RRC 디코더 생성 (asn1/README.md)
#   make clean
#
# 컴파일과 skeleton 생성은 권한이 필요 없음. BPF load 와 attach(portran 실행)는 root 권한이 필요함
CC       ?= cc
CLANG    ?= clang
BPFTOOL  ?= bpftool
BPFARCH  := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')
# -fPIC: 모든 .o 가 portran-telemetry.so 에 들어갈 수 있게 (정적 .a 를 공유 .so 로 묶음)
CFLAGS   := -std=c11 -D_DEFAULT_SOURCE -O2 -g -Wall -Wextra -fPIC -I src
LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null)
LIBBPF_LIBS   := $(shell pkg-config --libs libbpf 2>/dev/null || echo -lbpf)

BLD := build

all: $(BLD)/libcap.a $(BLD)/portran $(BLD)/portran-telemetry.so

# 1) BPF 오브젝트. 읽기 전용 헬퍼만 쓰는지 검사하고, 통과하지 못하면 산출물을 지워 다음 단계로 못 가게 함
$(BLD)/libcap/cap.bpf.o: src/libcap/cap.bpf.c src/libcap/cap_kern_abi.h tools/check_readonly.sh
	@mkdir -p $(@D)
	$(CLANG) -target bpf -mcpu=v3 -D__TARGET_ARCH_$(BPFARCH) -g -O2 -Wall $(LIBBPF_CFLAGS) \
	        -I/usr/include/$(shell uname -m)-linux-gnu -c $< -o $@.tmp
	SRC=$< ./tools/check_readonly.sh $@.tmp || (rm -f $@.tmp; false)
	mv $@.tmp $@

# 2) skeleton: struct cap_bpf 와 cap_bpf__open/load/destroy. BPF 오브젝트가 헤더 안에 바이트로 들어감
$(BLD)/libcap/cap.skel.h: $(BLD)/libcap/cap.bpf.o
	$(BPFTOOL) gen skeleton $< > $@.tmp && mv $@.tmp $@

# 3) 로더를 libcap.a 로
$(BLD)/libcap/cap.o: src/libcap/cap.c src/libcap/cap_kern_abi.h src/libcap/cap.h $(BLD)/libcap/cap.skel.h
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) -I $(BLD)/libcap -c $< -o $@

$(BLD)/libcap.a: $(BLD)/libcap/cap.o
	rm -f $@ && $(AR) rcs $@ $^

# ---- ASN.1 디코더 생성. 기본 타깃에는 없는 별도 타깃임 ----
#   문법과 패치와 glue 는 asn1/ 에 있고 자세한 설명은 asn1/README.md. 생성물은 build/gen/, 라이브러리는 build/
GEN      := $(BLD)/gen
ASN_DEFS := -DASN_DISABLE_BER_SUPPORT -DASN_DISABLE_OER_SUPPORT
# 디코더 전용 asn1c 생성 헤더 경로. F1AP 와 NGAP 와 RRC 는 같은 이름 skeleton 헤더가 있어 섞지 않음
#   -isystem: 생성물의 경고는 우리 책임이 아니므로 숨김. 우리 코드 경고만 봄
F1AP_INC := -isystem $(GEN)/f1ap
NGAP_INC := -isystem $(GEN)/ngap
RRC_INC  := -isystem $(GEN)/rrc
# 디코더 .c 는 asn1c walk 콜백이 균일 시그니처라 안 쓰는 매개변수가 생기므로 그 경고만 끔(-Wall -Wextra 는 유지)
DEC_CFLAGS := $(CFLAGS) $(ASN_DEFS) -Wno-unused-parameter
ASN_LIBS := $(BLD)/libf1ap.a $(BLD)/libnrrrc.a $(BLD)/libngap.a $(BLD)/libasn1skel.a
# asn1c 준비에서 문법, C, 정적 라이브러리 4개까지. 순서와 근거는 asn1/asn1.mk 와 asn1/README.md
#   매번 asn1.mk 를 부름(할 일이 없으면 곧 끝남). 입력이 바뀌었는지는 asn1.mk 가 내용(sha256)과 시각으로
#   판단하고(문법 파일은 시각만 바뀌어도 다시 변환함), 라이브러리가 지워졌으면 다시 만듬. 스탬프는
#   라이브러리가 실제로 새로 만들어졌을 때만 갱신함 - 매번 갱신하면 디코더가 매번 다시 컴파일됨
$(BLD)/.asn1libs.stamp: FORCE
	@$(MAKE) --no-print-directory -f asn1/asn1.mk BLD=$(BLD) CC='$(CC)' \
	        ASN_CFLAGS="-O2 -g0 -w -fPIC $(ASN_DEFS)"
	@for asn_lib in $(ASN_LIBS); do if [ ! -f $@ ] || [ $$asn_lib -nt $@ ]; then touch $@; fi; done
FORCE:
$(ASN_LIBS): $(BLD)/.asn1libs.stamp ;
asn1: $(BLD)/.asn1libs.stamp

# ---- 파이프라인 모듈 묶기 ----
#   libcap 은 위 특수 규칙(BPF skeleton 의존). 나머지 모듈은 아래 템플릿으로 src/lib<m>/*.c 에서
#   build/lib<m>.a 를 만듬. 폴더가 비어 있으면 .a 를 안 만들고 그만큼만 .so 에서 빠짐. .c 가 생기면 자동 편입
PLAIN_MODULES := sctp ap rrc nas obs telemetry sink
define MODULE_rule
$(BLD)/lib$(1).a: $(patsubst src/lib$(1)/%.c,$(BLD)/lib$(1)/%.o,$(wildcard src/lib$(1)/*.c))
	@mkdir -p $$(@D)
	rm -f $$@ && $(AR) rcs $$@ $$^
$(BLD)/lib$(1)/%.o: src/lib$(1)/%.c
	@mkdir -p $$(@D)
	$(CC) $(CFLAGS) -MMD -MP -c $$< -o $$@
endef
$(foreach m,$(PLAIN_MODULES),$(eval $(call MODULE_rule,$(m))))
# 자동 헤더 의존성: 위 -MMD 가 각 .o 옆에 .d(헤더 목록)를 남김. 이를 포함해 공유 헤더(common/types.h,
#   libcap/cap.h 등)가 바뀌면 해당 .o 를 다시 만듬. 없으면 스테일 .a 가 옛 ABI 로 남아 링크 뒤 크래시가 남
#   (예: cap_record 레이아웃 변경). -MP 는 지워진 헤더 때문에 멈추는 것을 막는 더미 타깃임
-include $(wildcard $(BLD)/lib*/*.d)

# 디코더 .o 는 공통 템플릿 대신 asn1 헤더 경로를 주는 명시 규칙으로 만듬(명시 규칙이 패턴 규칙에 우선)
$(BLD)/libap/f1ap.o: src/libap/f1ap.c src/libap/ap.h src/common/types.h $(BLD)/.asn1libs.stamp
	@mkdir -p $(@D)
	$(CC) $(DEC_CFLAGS) $(F1AP_INC) -c $< -o $@
$(BLD)/libap/ngap.o: src/libap/ngap.c src/libap/ap.h src/common/types.h $(BLD)/.asn1libs.stamp
	@mkdir -p $(@D)
	$(CC) $(DEC_CFLAGS) $(NGAP_INC) -c $< -o $@
$(BLD)/librrc/rrc.o: src/librrc/rrc.c src/librrc/rrc.h src/common/types.h $(BLD)/.asn1libs.stamp
	@mkdir -p $(@D)
	$(CC) $(DEC_CFLAGS) $(RRC_INC) -c $< -o $@

MODULES := cap $(PLAIN_MODULES)
# 지금 소스가 있는 모듈의 .a 만. 빈 폴더는 제외
PORTRAN_LIBS := $(foreach m,$(MODULES),$(if $(wildcard src/lib$(m)/*.c),$(BLD)/lib$(m).a))
# 디코더가 생기면 asn1 런타임도 함께 묶음. 그 전에는 불필요한 수십 MB 라 제외
PORTRAN_ASN  := $(if $(or $(wildcard src/libap/*.c),$(wildcard src/librrc/*.c)),$(ASN_LIBS))

# 배포물: 모든 모듈 .a 를 whole-archive 로 한 .so 에. soname 을 박아 어느 작업 디렉터리에서도 적재됨
$(BLD)/portran-telemetry.so: $(PORTRAN_LIBS) $(PORTRAN_ASN)
	$(CC) -shared -Wl,-soname,portran-telemetry.so -o $@ \
	      -Wl,--whole-archive $(PORTRAN_LIBS) $(PORTRAN_ASN) -Wl,--no-whole-archive $(LIBBPF_LIBS) -lm
portran-telemetry: $(BLD)/portran-telemetry.so

# 배포 실행 파일: libcap 에서 libsink 까지 전체를 묶어 표 I/II 를 냄
#   --start-group: 정적 .a 끼리 서로를 참조하므로 나열 순서를 따지지 않게 묶음
$(BLD)/portran: main.c $(PORTRAN_LIBS) $(PORTRAN_ASN)
	$(CC) $(CFLAGS) $< -o $@ -Wl,--start-group $(PORTRAN_LIBS) $(PORTRAN_ASN) -Wl,--end-group $(LIBBPF_LIBS) -lm
portran: $(BLD)/portran

clean:
	rm -rf $(BLD)

.PHONY: all asn1 portran portran-telemetry clean
