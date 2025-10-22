import types
import json
import builtins
from datetime import datetime

import os
import sys

# Ensure project root is on sys.path for imports
CURRENT_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, os.pardir))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import supervisor as sup


class FakeDynamoTable:
    def __init__(self):
        self.items = []
    def put_item(self, Item):
        self.items.append(Item)

class FakeDynamoResource:
    def __init__(self):
        self.tables = {}
    def Table(self, name):
        if name not in self.tables:
            self.tables[name] = FakeDynamoTable()
        return self.tables[name]

class FakeCloudWatch:
    def put_metric_data(self, **kwargs):
        # no-op in tests
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

class FakeBedrockRuntime:
    def converse(self, **kwargs):
        # Minimal shape expected by code
        return {
            "output": {
                "message": {
                    "content": [ {"text": "ok"} ]
                }
            },
            "stopReason": "end_turn"
        }

class FakeBoto3:
    def __init__(self):
        self._dynamo = FakeDynamoResource()
        self._cloudwatch = FakeCloudWatch()
        self._bedrock = FakeBedrockRuntime()
    def resource(self, name, region_name=None):
        if name == 'dynamodb':
            return self._dynamo
        raise NotImplementedError(name)
    def client(self, service_name, region_name=None):
        if service_name in ('cloudwatch',):
            return self._cloudwatch
        if service_name in ('bedrock-runtime','bedrock-agent-runtime','rds','ecs'):
            return self._bedrock
        raise NotImplementedError(service_name)


def make_supervisor_with_fakes(monkeypatch):
    # Patch boto3 used inside module
    fake = FakeBoto3()
    monkeypatch.setattr(sup, 'boto3', fake)
    # Build supervisor
    s = sup.SupervisorAgent()
    # Replace agents with simple stubs to avoid model calls
    class StubAgent:
        def __init__(self, name, status='success'):
            self.name = name
            self.status = status
        def process(self, incident, context):
            return {"agent": self.name, "timestamp": datetime.now().isoformat(), "status": self.status}
    s.agents = {
        sup.AgentRole.DETECTOR: StubAgent('detector'),
        sup.AgentRole.ANALYZER: StubAgent('analyzer'),
        sup.AgentRole.SOLUTION: StubAgent('solution'),
        sup.AgentRole.DEPLOYER: StubAgent('deployer', status='success'),
    }
    return s


def test_handle_incident_success(monkeypatch):
    s = make_supervisor_with_fakes(monkeypatch)
    incident = {
        "type": "database_connection_error",
        "severity": "high",
        "description": "Connection pool exhausted",
        "logs": ["[ERROR] Max connections reached"],
        "metadata": {"service": "api-gateway"}
    }
    result = s.handle_incident(incident)
    assert result["status"] == "resolved"
    assert "seconds" in result["resolution_time"]
    for role in ("detector","analyzer","solution","deployer"):
        assert role in result["agents_results"]


def test_handle_incident_agent_failure(monkeypatch):
    s = make_supervisor_with_fakes(monkeypatch)
    # Fail deployer
    class FailAgent:
        def process(self, incident, context):
            return {"agent": "deployer", "timestamp": datetime.now().isoformat(), "status": "failed"}
    s.agents[sup.AgentRole.DEPLOYER] = FailAgent()
    incident = {"type": "t", "severity": "low", "description": "d", "logs": [], "metadata": {}}
    result = s.handle_incident(incident)
    assert result["status"] in ("failed", "error")
