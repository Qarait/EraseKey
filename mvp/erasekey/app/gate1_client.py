from __future__ import annotations

import subprocess
import json
import logging
from typing import Dict, Any, Optional
from .config import settings

logger = logging.getLogger(__name__)

class Gate1Client:
    """
    Client for interacting with the Gate1 authoritative policy kernel.
    Communicates via subprocess CLI (mocked for MVP).
    """
    def __init__(self, cli_path: str = settings.gate1_cli_path):
        self.cli_path = cli_path

    def evaluate_policy(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes the gate1 CLI to evaluate a policy context.
        Fail-closed logic is implemented here.
        """
        # In a real integration, this would call a real binary.
        # For the MVP, if the binary is missing, we log and return a deny.
        try:
            # Prepare the command: gate1 evaluate-context --json '...'
            # For demonstration, we'll just simulate the failure or success call.
            # cmd = [self.cli_path, "evaluate-context", "--json", json.dumps(context)]
            # result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            # return json.loads(result.stdout)
            
            # Since gate1 is not actually installed in the environment, we simulate the 'Unavailable' state
            # which triggers the fail-closed logic.
            raise FileNotFoundError("Gate1 CLI not found")
            
        except FileNotFoundError:
            logger.error(f"Gate1 CLI not found at {self.cli_path}. Failing closed.")
            return {"decision": "deny", "reason_code": "POLICY_ENGINE_UNAVAILABLE"}
        except subprocess.CalledProcessError as e:
            logger.error(f"Gate1 evaluation failed: {e.stderr}. Failing closed.")
            return {"decision": "deny", "reason_code": "POLICY_ENGINE_ERROR"}
        except Exception as e:
            logger.error(f"Unexpected policy engine error: {str(e)}. Failing closed.")
            return {"decision": "deny", "reason_code": "INTERNAL_ERROR"}
