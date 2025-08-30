compile:
	chmod +x ./tools/compile.py
	./tools/compile.py ./examples/execve.py

install: 
	pip install -e .

clean:
	rm -rf build dist *.egg-info
	rm -rf examples/execve.ll examples/execve.o

all: install compile

.PHONY: all clean