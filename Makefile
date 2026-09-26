.PHONY: test demo gate-v02 build clean

test:
	PYTHONPATH=src python3 -m unittest discover -s tests -v

demo:
	PYTHONPATH=src bash scripts/demo.sh

gate-v02:
	PYTHONPATH=src python3 scripts/v02_gate.py

build:
	python3 -m build

clean:
	rm -rf .whyfs demo-work build dist *.egg-info src/*.egg-info
