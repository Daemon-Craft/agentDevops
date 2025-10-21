from strands_agent import Agent
import bedrock_agentcore
import boto3
import re
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()


class DetectorAgent():
    """An agent that uses AWS Bedrock to detect anomalies in data inputs."""

    def __init__(self, name, bedrock_model_name, aws_region):
        self.name = name
        self.bedrock_model_name = bedrock_model_name
        self.aws_region = aws_region
        self.bedrock_client = boto3.client('bedrock', region_name=self.aws_region)

    def detect_anomalies(self, data_input):
        prompt = f"Detect any anomalies in the following data:\n\nData: {data_input}\n\nProvide your response in JSON format with 'anomalies' as a list of detected issues."

        response = self.bedrock_client.invoke_model(
            modelId=self.bedrock_model_name,
            inputText=prompt,
            maxTokens=500,
            temperature=0.5
        )

        output_text = response['outputText']
        try:
            detection_result = json.loads(output_text)
            anomalies = detection_result.get('anomalies', [])
            return anomalies
        except json.JSONDecodeError:
            raise ValueError("Failed to parse Bedrock model output as JSON.")