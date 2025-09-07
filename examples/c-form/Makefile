BPF_CLANG := clang
CFLAGS := -O2 -emit-llvm -target bpf -c

SRC := ex3.bpf.c
OUT := ex3.bpf.ll
OBJECT := ex3.bpf.o

.PHONY: all clean

all: $(OUT)
	
object: $(SRC)
	$(BPF_CLANG) -O2 -g -target bpf -c $< -o $(OBJECT)

$(OUT): $(SRC) object
	$(BPF_CLANG) $(CFLAGS) -S $< -o $@

clean:
	rm -f $(OUT) $(OBJECT)
