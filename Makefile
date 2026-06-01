.PHONY: install run api test finetune docker-cli docker-api

install:
	python3 -m pip install -r requirements.txt

run:
	python3 app/main.py

api:
	uvicorn app.api:app --host 0.0.0.0 --port 8000 --reload

test:
	python3 -m pytest -q

finetune:
	python3 -m finetune

docker-cli:
	docker compose run --rm app

docker-api:
	docker compose --profile api up --build api
