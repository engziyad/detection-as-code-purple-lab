.PHONY: all lint unit test build ci new clean

all: ci

lint:            ## Validate rule metadata and logic
	python tools/validate.py

unit:            ## Unit-test the engine and converter
	python -m unittest discover -s tests

test:            ## Run every detection against its sample telemetry
	python tools/run_tests.py

build:           ## Generate KQL/SPL queries and ATT&CK coverage
	python tools/convert.py --all --out queries
	python tools/coverage.py

ci: lint unit test build   ## Everything the pipeline runs

new:             ## Scaffold a detection: make new ID=T1110.003 NAME=password_spraying
	python tools/new_detection.py $(ID) $(NAME)

clean:
	rm -rf reports __pycache__ tools/__pycache__ tests/__pycache__
