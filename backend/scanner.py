import subprocess
import tempfile
import json
import os

class SecurityScanner:
    def __init__(self):
        pass

    def scan_python(self, code_string):
        """
        Writes code to a temp file, runs Bandit static analysis, 
        and returns a structured list of vulnerabilities.
        """
        # Create a temporary Python file
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w", encoding="utf-8") as temp:
            temp.write(code_string)
            temp_path = temp.name

        issues = []
        try:
            # Run Bandit: -f json outputs JSON format, -q suppresses terminal noise
            result = subprocess.run(
                ["bandit", "-f", "json", "-q", temp_path],
                capture_output=True,
                text=True
            )
            
            # Bandit returns exit code 1 if issues are found. 
            # We just parse the stdout JSON regardless.
            if result.stdout:
                report = json.loads(result.stdout)
                for res in report.get("results", []):
                    cwe = res.get("issue_cwe", {}).get("id", 0)
                    issues.append({
                        "tool": "Bandit",
                        "line": res.get("line_number"),
                        "severity": res.get("issue_severity"),
                        "cwe": f"CWE-{cwe}" if cwe else "Unknown",
                        "description": res.get("issue_text"),
                    })
        except Exception as e:
            print(f"Scanner error: {e}")
        finally:
            # Always clean up the temp file
            os.unlink(temp_path)
            
        return issues

    def calculate_safety_score(self, issues):
        """
        Addition #3: Product Layer. 
        Calculates a 0-100 score based on the number and severity of vulnerabilities.
        """
        if not issues:
            return 100
            
        score = 100
        for issue in issues:
            sev = issue.get("severity", "LOW").upper()
            if sev == "HIGH":
                score -= 40
            elif sev == "MEDIUM":
                score -= 20
            else:
                score -= 10
                
        return max(0, score) # Score cannot drop below 0

if __name__ == "__main__":
    scanner = SecurityScanner()
    
    # Let's test it with a classic vulnerable snippet!
    vulnerable_code = '''
import subprocess
from flask import request

def run_user_cmd():
    user_input = request.args.get("cmd")
    # VULNERABILITY: Executing raw user input with shell=True
    subprocess.call(user_input, shell=True)
'''
    print("Scanning test code with Bandit...")
    issues = scanner.scan_python(vulnerable_code)
    
    print(f"\nFound {len(issues)} issues.")
    for issue in issues:
        print(f"⚠️  Line {issue['line']}: [{issue['severity']}] {issue['cwe']} - {issue['description']}")
        
    score = scanner.calculate_safety_score(issues)
    print(f"\n🛡️  Safety Score: {score}/100")
