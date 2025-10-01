install:
	pip install -e .

clean:
	rm -rf build dist *.egg-info
	rm -rf examples/*.ll examples/*.o

all: clean install

.PHONY: all clean
