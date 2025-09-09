compile:
	chmod +x ./tools/compile.py
	./tools/compile.py ./examples/execve3.py

install: 
	pip install -e .

clean:
	rm -rf build dist *.egg-info
	rm -rf examples/*.ll examples/*.o

all: install compile

.PHONY: all clean
