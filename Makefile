compile:
	chmod +x ./tools/compile.py
	./tools/compile.py ./examples/execve2.py

install: 
	pip install -e .

clean:
	rm -rf build dist *.egg-info
	rm -rf examples/*.ll examples/*.o

all: install compile

.PHONY: all clean