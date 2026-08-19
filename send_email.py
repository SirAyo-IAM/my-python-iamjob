import os
import base64
import requests

CSV_FILE = "uk_iam_results.csv"

brevo_api_key = os.environ["BREVO_API_KEY"]
report_email = os.environ["REPORT_EMAIL"]
sender_email = os.environ["BREVO_SENDER_EMAIL"]

with open(CSV_FILE, "rb") as file:
    csv_content = base64.b64encode(file.read()).decode("utf-8")

payload = {
    "sender": {
        "name": "UK IAM Hunter",
        "email": send_email
    },
    "to": [
        {
            "email": report_email
        }
    ],
    "subject": "UK IAM Hunter - Daily Results",
    "textContent": """Your daily UK IAM/PAM job scan is complete.

The attached CSV contains today's verified IAM/PAM job openings.

Regards,
UK IAM Hunter
""",
    "attachment": [
        {
            "content": csv_content,
            "name": "uk_iam_results.csv"
        }
    ]
}

response = requests.post(
    "https://api.brevo.com/v3/smtp/email",
    headers={
        "accept": "application/json",
        "api-key": brevo_api_key,
        "content-type": "application/json"
    },
    json=payload,
    timeout=30
)

if response.status_code not in (200, 201):
    print("Brevo error:")
    print(response.text)
    raise SystemExit(1)

print("Email sent successfully.")
