# agentDevops

Multi-agent DevOps incident manager using AWS Bedrock Runtime and a Supervisor orchestrator.

## Quick start

- Local run (uses your AWS credentials and .env):
	- Optional: create and activate a virtual environment
	- Install dependencies from `requirements.txt`
	- Run `python supervisor.py` to execute the sample incident flow locally

- Deploy (AWS SAM):
	- Ensure AWS CLI and SAM CLI are installed and configured
	- Build with SAM, then deploy the stack `devops-incident-manager`

## Environment variables

Set these in your shell or a local `.env` file (loaded by the app):

- AWS_REGION (or AWS_DEFAULT_REGION)
- DYNAMODB_TABLE or INCIDENT_TABLE_NAME (defaults to `incident-reports` from the template)
- INCIDENT_METRICS_NAMESPACE (default: `DevOpsIncidentManager`)
- BEDROCK_MODEL_ID (peut être soit un ID de modèle, soit l'ARN d'un Inference Profile)
- BEDROCK_INFERENCE_PROFILE_ARN (optionnel; si défini, il sera utilisé comme modelId en priorité)

Remarque: Certains modèles récents exigent un Inference Profile. En cas d'erreur ValidationException indiquant que l'on-demand n'est pas supporté, créez un Inference Profile dans la console Bedrock puis:
- soit mettez son ARN dans `BEDROCK_INFERENCE_PROFILE_ARN`
- soit remplacez `BEDROCK_MODEL_ID` par cet ARN (il sera accepté comme `modelId`)

## Lambda handler

The SAM template points the function handler to `supervisor.lambda_handler`.

## Notes for Windows users

- Use PowerShell or Windows Terminal for local runs.
- The `deploy.sh` script is Bash; run it in Git Bash or WSL, or execute the SAM commands manually.

## Make targets

- `make local` runs `python supervisor.py`
- `make deploy` builds and deploys via SAM (guided on first run)

## Testing the flow locally

You can modify the sample incident inside `supervisor.py` in `main()` to simulate different scenarios.
