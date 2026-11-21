PY=.venv/bin/python

venv:
	python3 -m venv .venv
	$(PY) -m pip install -U pip
	$(PY) -m pip install -e ".[dev]"

test:
	$(PY) -m pytest

bench:
	$(PY) -m kmssuite.bench.run_bench --out bench/results

report:
	$(PY) -m kmssuite.bench.report

demo-local:
	bash scripts/demo_local.sh

deploy-kms:
	bash deploy/deploy.sh kms

deploy-prov:
	bash deploy/deploy.sh prov

deploy-client:
	bash deploy/deploy.sh client

deploy-all: deploy-kms deploy-prov deploy-client

smoke:
	bash deploy/smoke_test.sh
