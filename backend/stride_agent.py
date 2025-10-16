import os
import json
from models import Threat
from google import genai

client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

PROMPT_TEMPLATE = """
You are a security expert that performs STRIDE threat modeling.

Given the following system architecture description, identify potential threats using the STRIDE framework.

Return a JSON array of objects like:
[
  {{
    "component": "Login API",
    "type": "Tampering",
    "description": "The API may be vulnerable to input tampering such as SQL injection."
  }},
  ...
]

Important: Output ONLY the JSON. Do not include any explanation, markdown formatting, or code blocks.

System description:
{flow_text}
"""

def extract_json_block(text: str) -> str:
    """
    Attempt to extract a JSON array from a Gemini response, even if it's wrapped in markdown or extra text.
    """
    start = text.find("[")
    end = text.rfind("]")
    if start != -1 and end != -1 and end > start:
        return text[start:end+1]
    return text

def analyze_system_flow(flow_text: str):
    prompt = PROMPT_TEMPLATE.format(flow_text=flow_text)

    try:
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt
        )

        raw_text = response.text.strip()
        print("DEBUG: Gemini returned:\n", raw_text)  # Show raw output for debugging

        # Try to extract the JSON part
        cleaned_text = extract_json_block(raw_text)

        # Parse JSON
        threats_raw = json.loads(cleaned_text)

        threats = []
        for t in threats_raw:
            threats.append(Threat(
                component=t.get("component", "Unknown"),
                type=t.get("type", "Unknown"),
                description=t.get("description", "No description")
            ))
        return threats

    except json.JSONDecodeError as e:
        return [Threat(
            component="Error",
            type="Parsing",
            description=f"Invalid JSON returned by Gemini: {str(e)}"
        )]

    except Exception as e:
        return [Threat(
            component="Error",
            type="ModelCall",
            description=f"Error during Gemini response parsing: {str(e)}"
        )]

if __name__ == "__main__":
    sample_input = """
    A user logs into an online banking app. The login request is sent to an authentication API, which verifies credentials and issues a session token. The user then transfers funds, which calls a backend service connected to a transaction database.
    """
    result = analyze_system_flow(sample_input)
    for r in result:
        print(r)
