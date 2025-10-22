param(
    [string]$StackName = "devops-incident-manager",
    [string]$Region = $env:AWS_REGION
)

Write-Host "Deploying DevOps Multi-Agent Incident Manager" -ForegroundColor Cyan

if (-not (Get-Command aws -ErrorAction SilentlyContinue)) {
    Write-Error "AWS CLI is not installed"; exit 1
}
if (-not (Get-Command sam -ErrorAction SilentlyContinue)) {
    Write-Error "AWS SAM CLI is not installed"; exit 1
}
if (-not $Region) { $Region = "us-east-1" }

Write-Host "Building..." -ForegroundColor Yellow
sam build
if ($LASTEXITCODE -ne 0) { Write-Error "Build failed"; exit 1 }

Write-Host "Deploying..." -ForegroundColor Yellow
sam deploy --guided --stack-name $StackName --region $Region
if ($LASTEXITCODE -ne 0) { Write-Error "Deploy failed"; exit 1 }

Write-Host "Done." -ForegroundColor Green
