from strands.agent import Agent
import bedrock_agentcore
import boto3
import json
from botocore.exceptions import ClientError
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()

class SupervisorAgent(Agent):
    def __init__(self, name, bedrock_model_name, aws_region):
        super().__init__(name)
        self.bedrock_model_name = bedrock_model_name
        self.aws_region = aws_region
        self.bedrock_client = boto3.client('bedrock', region_name=self.aws_region)

    def analyze_and_delegate(self, task_description):
        prompt = f"Analyze the following task and determine the best specialized agent to handle it:\n\nTask: {task_description}\n\nProvide your response in JSON format with 'agent_type' and 'instructions'."

        response = self.bedrock_client.invoke_model(
            modelId=self.bedrock_model_name,
            inputText=prompt,
            maxTokens=500,
            temperature=0.5
        )

        output_text = response['outputText']
        try:
            analysis = json.loads(output_text)
            agent_type = analysis.get('agent_type')
            instructions = analysis.get('instructions')
            return agent_type, instructions
        except json.JSONDecodeError:
            raise ValueError("Failed to parse Bedrock model output as JSON.")