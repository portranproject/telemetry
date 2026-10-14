CC      := clang
BPFTOOL ?= bpftool
ARCH    := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')
CFLAGS  := -g -O2 -Wall

# ---- asn1c: 원본 빌드 ----
ASN1C_REPO   := https://github.com/mouse07410/asn1c
ASN1C_COMMIT := 940dd5fa9f3917913fd487b13dfddfacd0ded06e
ASN1C_DIR    := third_party/asn1c
ASN1C        := $(ASN1C_DIR)/asn1c/asn1c
# F1AP 는 APER 만 사용
ASN1C_OPTS   := -gen-APER -no-gen-UPER -no-gen-BER -no-gen-OER -no-gen-JER \
                -fcompound-names -findirect-choice -fno-include-deps -no-gen-example

# ---- F1AP 문법: 3GPP TS 38.473 V18.8.0 (OCUDU 와 같은 판) 원문에서 추출 ----
F1AP_ASN := asn1/f1ap-18.8.0.asn

GEN_SRCS = $(wildcard gen/*.c)
GEN_OBJS = $(patsubst gen/%.c,build/%.o,$(GEN_SRCS))

all: f1tap

# 1) asn1c 컴파일러
$(ASN1C):
	[ -d $(ASN1C_DIR) ] || git clone $(ASN1C_REPO) $(ASN1C_DIR)
	git -C $(ASN1C_DIR) checkout -q $(ASN1C_COMMIT)
	cd $(ASN1C_DIR) && autoreconf -i && ./configure -q && $(MAKE) -s

# 2) ASN.1 → C (asn1c 가 생성한 코드와 asn1c 런타임 skeleton 을 그대로 쓴다).
gen/.stamp: $(F1AP_ASN) | $(ASN1C)
	rm -rf gen && mkdir gen
	ASN1C_PREFIX=F1AP_ $(ASN1C) -S $(ASN1C_DIR)/skeletons $(ASN1C_OPTS) -D gen $< > build-asn1c.log 2>&1 \
	    || (tail -5 build-asn1c.log; false)
	touch $@

# 3) 생성 코드 → 정적 라이브러리. gen/*.c 목록은 생성 뒤에야 보이므로 make 를 한 번 더 띄운다.
build/libf1ap.a: gen/.stamp
	$(MAKE) --no-print-directory asn1lib
asn1lib: $(GEN_OBJS)
	@rm -f build/libf1ap.a && ar rcs build/libf1ap.a $^ && echo "  AR build/libf1ap.a ($(words $^) 개)"
build/%.o: gen/%.c
	@mkdir -p build
	@$(CC) -O2 -w -Igen -c $< -o $@

# 4) 커널 BPF + 스켈레톤.
f1tap.bpf.o: f1tap.bpf.c f1tap.h
	$(CC) -target bpf -D__TARGET_ARCH_$(ARCH) -g -O2 -Wall -I/usr/include/$(shell uname -m)-linux-gnu -c $< -o $@
f1tap.skel.h: f1tap.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

# 5) 유저 프로그램
f1tap: f1tap.c f1tap.h f1tap.skel.h build/libf1ap.a
	$(CC) $(CFLAGS) -I. -Igen f1tap.c -o $@ build/libf1ap.a -lbpf -lelf -lz -lm

# asn1c 런타임이 GitHub 원본과 바이트 단위로 같은지 확인
check-asn1c:
	@n=0; for f in gen/*; do b=$${f##*/}; case $$b in F1AP_*|asn_config.h|Makefile.am.libasncodec) continue ;; esac; \
	  cmp -s $$f $(ASN1C_DIR)/skeletons/$$b || { echo "다름: $$b"; exit 1; }; n=$$((n+1)); done; \
	  echo "asn1c 런타임 $$n 개 파일 = $(ASN1C_REPO) @$(ASN1C_COMMIT) 원본과 동일"

# clean     : 생성물 전부 삭제(gen/, build/, 로그, 실행 파일). 남는 것 = 소스 + asn1/ + tests/ + third_party/
#             → 다음 make 때 asn1c 로 gen/ 재생성(약 4분)
# distclean : third_party/asn1c 까지 삭제 → 다음 make 때 GitHub 에서 다시 받음(인터넷 필요)
clean:
	rm -rf f1tap f1tap.bpf.o f1tap.skel.h build build-asn1c.log gen
distclean: clean
	rm -rf third_party
.PHONY: all asn1lib check-asn1c clean distclean
