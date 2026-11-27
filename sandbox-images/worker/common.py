import json, sys

def progress(stage, msg, **data):
    """One line of progress the orchestrator streams to the dashboard."""
    print("PROGRESS " + json.dumps({"stage": stage, "msg": msg, **data}), flush=True)

def result(obj):
    print("RESULT " + json.dumps(obj), flush=True)

def fail(msg):
    print("RESULT " + json.dumps({"error": msg}), flush=True)
    sys.exit(1)
