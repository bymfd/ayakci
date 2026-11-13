.PHONY: test selftest extract clean install

install:
	pip install -r requirements.txt

test:
	python -m unittest discover -s . -p "test_*.py"

selftest:
	python ayakci.py selftest

extract:
	python ayakci.py extract examples/ --no-serve

clean:
	rm -rf __pycache__ *.pyc candidates.json legacy-report.json