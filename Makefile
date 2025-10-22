.PHONY: install deploy test clean

install:
	pip install -r requirements.txt

test:
	python -m pytest tests/ -v

deploy:
	sam build
	sam deploy --guided --stack-name devops-incident-manager

local:
	python supervisor.py

invoke-local:
	sam local invoke IncidentManagerFunction -e events/test_incident.json

start-api:
	sam local start-api

clean:
	rm -rf .aws-sam/
	rm -rf __pycache__/
	find . -type f -name '*.pyc' -delete

validate:
	sam validate
	cfn-lint template.yaml

logs:
	sam logs -n IncidentManagerFunction --stack-name devops-incident-manager --tail