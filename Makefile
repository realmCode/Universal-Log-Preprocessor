.PHONY: help install test demo clean docker-build docker-up docker-down

help:
	@echo "ULPF — Universal Log Pre-processing Framework"
	@echo ""
	@echo "Targets:"
	@echo "  install       Install Python dependencies"
	@echo "  test          Run tests"
	@echo "  demo          Generate demo logs and run pipeline"
	@echo "  demo-full     Run the full demo sequence"
	@echo "  clean         Remove generated files"
	@echo "  docker-build  Build Docker image"
	@echo "  docker-up     Start full stack with Docker Compose"
	@echo "  docker-down   Stop Docker Compose stack"
	@echo "  docker-demo   Start stack + run demo log generator"

install:
	pip install -r requirements.txt

test:
	python -m pytest tests/ -v --tb=short

demo:
	python scripts/generate_demo_logs.py data/sample_logs/demo_mixed.log 20
	python pathway_app.py --input data/sample_logs/demo_mixed.log --output output/demo_output.jsonl --limit 80

demo-full:
	python scripts/run_demo.py all

clean:
	rm -rf output/*.jsonl
	rm -rf drain3_state/*
	rm -rf data/sample_logs/demo_mixed.log
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

docker-build:
	docker build -t ulpf:latest .

docker-up:
	docker compose -f deploy/docker-compose.yml up -d
	@echo "Waiting for services to start..."
	@sleep 15
	@echo "Kafka at localhost:9092"
	@echo "ULPF worker running. Check logs: docker logs ulpf-worker"

docker-down:
	docker compose -f deploy/docker-compose.yml down

docker-demo:
	docker compose -f deploy/docker-compose.yml --profile demo up --build
