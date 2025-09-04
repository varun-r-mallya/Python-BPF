BPF_CLANG := clang
CFLAGS := -O2 -emit-llvm -target bpf -c

SRC := example.bpf.c
OUT := example.bpf.ll
OBJECT := example.bpf.o

.PHONY: all clean

all: $(OUT)
	
object: $(SRC)
	$(BPF_CLANG) -O2 -target bpf -c $< -o $(OBJECT)

$(OUT): $(SRC) object
	$(BPF_CLANG) $(CFLAGS) -S $< -o $@

clean:
	rm -f $(OUT) $(OBJECT)
