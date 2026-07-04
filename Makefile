.PHONY: install dev test test-unit test-smoke test-integration lint format typecheck docker cert clean

install:
	pip install -e .

dev:
	pip install -e ".[all]"

test:
	python3 -m pytest -m "not integration"

test-unit:
	python3 -m pytest -m "not smoke and not integration"

test-smoke:
	python3 -m pytest -m smoke

test-integration:
	python3 -m pytest tests/integration/ -v --headed=false

lint:
	ruff check .

format:
	ruff format .

typecheck:
	mypy identity_provider_server/

docker:
	docker build -t identity-provider-server .

cert:
	openssl req -x509 -newkey rsa:2048 \
		-keyout data/idp.key -out data/idp.crt \
		-days 3650 -nodes -subj "/CN=local-idp"

clean:
	rm -rf __pycache__ .pytest_cache .coverage .mypy_cache .ruff_cache
	rm -rf identity_provider_server/__pycache__ tests/__pycache__
	rm -rf *.egg-info dist build
