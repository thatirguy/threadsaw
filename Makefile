.PHONY: test install docker doctor

install:
	python -m pip install -e .

test:
	PYTHONPATH=src pytest -q

docker:
	docker build -t threadsaw:1.3.0 .

doctor:
	PYTHONPATH=src python -m threadsaw doctor
