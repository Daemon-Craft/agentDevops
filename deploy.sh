#!/bin/bash

# ==========================================
# DevOps Multi-Agent Deployment Script
# ==========================================

set -e

echo "Deploying DevOps Multi-Agent Incident Manager"
echo "=================================================="

# ANSI colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Prerequisites check
check_requirements() {
    echo -e "${YELLOW}Checking prerequisites...${NC}"
    
    # Check AWS CLI
    if ! command -v aws &> /dev/null; then
        echo -e "${RED}AWS CLI is not installed${NC}"
        exit 1
    fi
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}Python 3 is not installed${NC}"
        exit 1
    fi
    
    # Check SAM CLI
    if ! command -v sam &> /dev/null; then
        echo -e "${RED}SAM CLI is not installed${NC}"
        echo "Install with: pip install aws-sam-cli"
        exit 1
    fi
    
    echo -e "${GREEN}All prerequisites are satisfied${NC}"
}

# AWS configuration
setup_aws() {
    echo -e "${YELLOW}Configuring AWS...${NC}"
    
    # Vérifier les credentials AWS
    if ! aws sts get-caller-identity &> /dev/null; then
        echo -e "${RED}AWS credentials are not configured${NC}"
        echo "Run: aws configure"
        exit 1
    fi
    
    # Obtenir l'account ID et la région
    export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
    export AWS_REGION=${AWS_REGION:-us-east-1}
    
    echo -e "${GREEN}AWS Account: $AWS_ACCOUNT_ID${NC}"
    echo -e "${GREEN}Region: $AWS_REGION${NC}"
}

# Check Bedrock access
enable_bedrock() {
    echo -e "${YELLOW}Checking Bedrock access...${NC}"
    
    # Vérifier l'accès à Bedrock
    if aws bedrock list-foundation-models --region $AWS_REGION &> /dev/null; then
        echo -e "${GREEN}Bedrock is accessible${NC}"
    else
        echo -e "${YELLOW}Bedrock might not be enabled${NC}"
        echo "Go to AWS Console > Bedrock > Model access to enable Claude"
    fi
}

# Setup Python environment
setup_python() {
    echo -e "${YELLOW}Setting up Python environment...${NC}"
    
    # Créer virtual environment
    if [ ! -d ".venv" ]; then
        python3 -m venv .venv
    fi
    
    # Activer et installer dépendances
    source .venv/bin/activate
    pip install -q --upgrade pip
    pip install -q -r requirements.txt
    
    echo -e "${GREEN}Python environment configured${NC}"
}

# Local test
test_local() {
    echo -e "${YELLOW}Running local test...${NC}"
    
    # Créer un incident de test
    cat > test_incident.json << EOF
{
    "type": "database_connection_error",
    "severity": "high",
    "description": "Connection pool exhausted",
    "logs": [
        "[ERROR] Max connections reached",
        "[ERROR] ConnectionPoolExhaustedException"
    ],
    "metadata": {
        "service": "api-gateway"
    }
}
EOF
    
    # Run local
    python supervisor.py
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Local test succeeded${NC}"
    else
        echo -e "${RED}Local test failed${NC}"
        exit 1
    fi
}

# Deploy with SAM
deploy_sam() {
    echo -e "${YELLOW}Deploying to AWS...${NC}"
    
    # Build
    echo "Building..."
    sam build
    
    # Deploy
    echo "Deploying..."
    sam deploy \
        --stack-name devops-incident-manager \
        --capabilities CAPABILITY_IAM \
        --parameter-overrides \
            "ParameterKey=Environment,ParameterValue=production" \
        --no-confirm-changeset \
        --no-fail-on-empty-changeset
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Deployment succeeded${NC}"
        
        # Récupérer les outputs
        API_ENDPOINT=$(aws cloudformation describe-stacks \
            --stack-name devops-incident-manager \
            --query 'Stacks[0].Outputs[?OutputKey==`ApiEndpoint`].OutputValue' \
            --output text)
        
        FUNCTION_ARN=$(aws cloudformation describe-stacks \
            --stack-name devops-incident-manager \
            --query 'Stacks[0].Outputs[?OutputKey==`FunctionArn`].OutputValue' \
            --output text)
        
        echo -e "${GREEN}API Endpoint: $API_ENDPOINT${NC}"
        echo -e "${GREEN}Function ARN: $FUNCTION_ARN${NC}"
    else
        echo -e "${RED}Deployment failed${NC}"
        exit 1
    fi
}

# Test the deployed API
test_deployed() {
    echo -e "${YELLOW}Testing deployed API...${NC}"
    
    if [ -z "$API_ENDPOINT" ]; then
        echo -e "${YELLOW}No API endpoint found${NC}"
        return
    fi
    
    # Envoyer un incident de test
    curl -X POST "$API_ENDPOINT" \
        -H "Content-Type: application/json" \
        -H "x-api-key: ${API_KEY}" \
        -d @test_incident.json
    
    echo -e "${GREEN}API test completed${NC}"
}

# Configure monitoring
setup_monitoring() {
    echo -e "${YELLOW}Configuring monitoring...${NC}"
    
    # Créer une alarme CloudWatch
    aws cloudwatch put-metric-alarm \
        --alarm-name "IncidentManagerErrors" \
        --alarm-description "Alert when Lambda errors occur" \
        --metric-name Errors \
        --namespace AWS/Lambda \
        --statistic Sum \
        --period 60 \
        --threshold 1 \
        --comparison-operator GreaterThanThreshold \
        --dimensions Name=FunctionName,Value=devops-incident-manager \
        --evaluation-periods 1
    
    echo -e "${GREEN}Monitoring configured${NC}"
}

# Final instructions
show_instructions() {
    echo ""
    echo "=========================================="
    echo -e "${GREEN}DEPLOYMENT COMPLETED SUCCESSFULLY${NC}"
    echo "=========================================="
    echo ""
    echo "NEXT STEPS:"
    echo "1. Test the API with:"
    echo "   curl -X POST $API_ENDPOINT -H 'Content-Type: application/json' -d @test_incident.json"
    echo ""
    echo "2. View logs:"
    echo "   sam logs -n IncidentManagerFunction --stack-name devops-incident-manager --tail"
    echo ""
    echo "3. CloudWatch Dashboard:"
    echo "   https://console.aws.amazon.com/cloudwatch/home?region=$AWS_REGION#dashboards:name=DevOpsIncidentManager"
    echo ""
    echo "4. For hackathon submission:"
    echo "   - Demo video (max 3 min)"
    echo "   - Architecture diagram"
    echo "   - Code repository (GitHub)"
    echo "   - Live demo URL"
    echo ""
}

# Main menu
main() {
    echo ""
    echo "Choose an option:"
    echo "1) Full deployment"
    echo "2) Local test only"
    echo "3) Deploy only (no tests)"
    echo "4) Configure monitoring"
    echo "5) Clean up resources"
    read -p "Option: " option
    
    case $option in
        1)
            check_requirements
            setup_aws
            enable_bedrock
            setup_python
            test_local
            deploy_sam
            test_deployed
            setup_monitoring
            show_instructions
            ;;
        2)
            check_requirements
            setup_python
            test_local
            ;;
        3)
            check_requirements
            setup_aws
            deploy_sam
            show_instructions
            ;;
        4)
            setup_aws
            setup_monitoring
            ;;
        5)
            echo -e "${YELLOW}Deleting resources...${NC}"
            sam delete --stack-name devops-incident-manager --no-prompts
            echo -e "${GREEN}Resources deleted${NC}"
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            exit 1
            ;;
    esac
}

# Exécution
main