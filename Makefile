.PHONY: install ingest run test cov lint docker

install:
	pip install -r requirements.txt

ingest:
	python -m tig.ingest

run:
	uvicorn tig.api:app --reload --port 8000

test:
	pytest

cov:
	pytest --cov=tig --cov-report=term-missing

lint:
	ruff check tig tests

docker:
	docker compose up --build
