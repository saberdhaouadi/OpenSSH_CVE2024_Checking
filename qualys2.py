import xml.etree.ElementTree as ET
import requests
import json
from datetime import datetime, timedelta
import base64
import getpass

# Jira configuration
JIRA_URL = "https://your-domain.atlassian.net"  # Replace with your Jira instance URL
JIRA_PROJECT_KEY = "YOUR_PROJECT_KEY"  # Replace with your Jira project key
JIRA_ISSUE_TYPE = "Task"  # Adjust (e.g., Bug, Task)
JIRA_API_TOKEN = getpass.getpass("Enter your Jira API token: ")  # Secure input
JIRA_USERNAME = "your.email@example.com"  # Replace with your Jira email

# Qualys XML report path
QUALYS_REPORT_PATH = "path/to/your/qualys_report.xml"  # Replace with XML file path

# Due date and priority mapping based on CVSS score
CVSS_DUE_DAYS = {
    8: {"days": 15, "priority": "Highest"},
    6: {"days": 30, "priority": "High"},
    4: {"days": 45, "priority": "Medium"},
    2: {"days": 60, "priority": "Low"},
    1: {"days": 90, "priority": "Lowest"}
}

def get_jira_auth_headers():
    """Generate headers for Jira API authentication."""
    auth_string = f"{JIRA_USERNAME}:{JIRA_API_TOKEN}"
    auth_encoded = base64.b64encode(auth_string.encode()).decode()
    return {
        "Content-Type": "application/json",
        "Authorization": f"Basic {auth_encoded}"
    }

def check_duplicate_issue(summary):
    """Check if an issue with the same summary exists."""
    jql = f'project = {JIRA_PROJECT_KEY} AND summary ~ "{summary}"'
    url = f"{JIRA_URL}/rest/api/2/search"
    params = {"jql": jql}
    try:
        response = requests.get(url, headers=get_jira_auth_headers(), params=params)
        response.raise_for_status()
        issues = response.json().get("issues", [])
        return len(issues) > 0
    except requests.RequestException as e:
        print(f"Error checking duplicates: {e}")
        return False

def create_jira_issue(vuln_data, ec2_instance):
    """Create a Jira issue for a vulnerability on an EC2 instance."""
    url = f"{JIRA_URL}/rest/api/2/issue"
    summary = f"Qualys Vulnerability: {vuln_data['title']} on EC2 {ec2_instance['hostname']} (QID: {vuln_data['qid']})"
    
    # Skip duplicates
    if check_duplicate_issue(summary):
        print(f"Skipping duplicate issue: {summary}")
        return

    # Calculate due date and priority based on CVSS
    cvss_base = float(vuln_data.get("cvss_base", 1))
    due_days = 90  # Default
    priority = "Lowest"  # Default
    for threshold, config in CVSS_DUE_DAYS.items():
        if cvss_base >= threshold:
            due_days = config["days"]
            priority = config["priority"]
            break
    
    due_date = (datetime.now() + timedelta(days=due_days)).strftime("%Y-%m-%d")

    # Construct issue payload
    payload = {
        "fields": {
            "project": {"key": JIRA_PROJECT_KEY},
            "issuetype": {"name": JIRA_ISSUE_TYPE},
            "summary": summary,
            "description": (
                f"*EC2 Instance*: {ec2_instance['hostname']} ({ec2_instance['ip']})\n"
                f"*EC2 Instance ID*: {ec2_instance.get('instance_id', 'N/A')}\n"
                f"*QID*: {vuln_data['qid']}\n"
                f"*Severity*: {vuln_data['severity']}\n"
                f"*CVSS Base*: {vuln_data.get('cvss_base', 'N/A')}\n"
                f"*First Detected*: {vuln_data.get('first_detected', 'N/A')}\n"
                f"*Last Detected*: {vuln_data.get('last_detected', 'N/A')}\n"
                f"*Threat*: {vuln_data.get('threat', 'N/A')}\n"
                f"*Impact*: {vuln_data.get('impact', 'N/A')}\n"
                f"*Solution*: {vuln_data.get('solution', 'N/A')}\n"
            ),
            "priority": {"name": priority},
            "duedate": due_date,
            # Add custom fields (replace customfield_XXXXX with your field IDs)
            # "customfield_10200": vuln_data.get("cve_id", ""),
        }
    }

    try:
        response = requests.post(url, headers=get_jira_auth_headers(), data=json.dumps(payload))
        response.raise_for_status()
        issue_key = response.json().get("key")
        print(f"Created Jira issue: {issue_key}")
    except requests.RequestException as e:
        print(f"Failed to create issue for QID {vuln_data['qid']} on {ec2_instance['hostname']}: {e}")

def parse_qualys_report(xml_path):
    """Parse Qualys XML report and extract EC2 instance vulnerabilities."""
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        ec2_vulnerabilities = []

        # Iterate through hosts (adjust path based on your XML structure)
        for host in root.findall(".//HOST"):
            ip = host.findtext("IP", "N/A")
            hostname = host.findtext("DNS", "Unknown Host")
            instance_id = host.findtext("EC2_INSTANCE_ID", "N/A")  # Adjust if EC2 ID is elsewhere
            ec2_instance = {"ip": ip, "hostname": hostname, "instance_id": instance_id}

            # Find vulnerabilities for this host
            for vuln in host.findall(".//VULN"):
                vuln_data = {
                    "qid": vuln.get("QID", "N/A"),
                    "title": vuln.findtext("TITLE", "Unknown Vulnerability"),
                    "severity": vuln.findtext("SEVERITY", "N/A"),
                    "cvss_base": vuln.findtext("CVSS_BASE", "1"),
                    "first_detected": vuln.findtext("FIRST_DETECTED", "N/A"),
                    "last_detected": vuln.findtext("LAST_DETECTED", "N/A"),
                    "threat": vuln.findtext("THREAT", "N/A"),
                    "impact": vuln.findtext("IMPACT", "N/A"),
                    "solution": vuln.findtext("SOLUTION", "N/A"),
                    "cve_id": vuln.findtext("CVE_LIST/CVE/ID", "N/A")
                }
                ec2_vulnerabilities.append((ec2_instance, vuln_data))
        
        return ec2_vulnerabilities
    except ET.ParseError as e:
        print(f"Error parsing XML file: {e}")
        return []
    except Exception as e:
        print(f"Unexpected error: {e}")
        return []

def main():
    """Main function to process Qualys report and create Jira tickets for EC2 vulnerabilities."""
    ec2_vulnerabilities = parse_qualys_report(QUALYS_REPORT_PATH)
    if not ec2_vulnerabilities:
        print("No EC2 vulnerabilities found or error parsing report.")
        return

    for ec2_instance, vuln in ec2_vulnerabilities:
        create_jira_issue(vuln, ec2_instance)

if __name__ == "__main__":
    main()