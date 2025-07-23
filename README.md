This project parses .pcap network traffic data and uses google Gemini AI to classify incidents and analyse them, log all findings and simulates Jira ticket creation for alerts

FEATURES 
- Parses packet data from .pcap files 
- Extract HTTP headers, source and destination IPs and ports
- Sends descriptions to Gemini AI to analyze incidents 
- Logs all packets to events.csv
- Logs extracted alerts to alerts.csv (Incident name, criticality, confidence)
- Simulates Jira ticket creation for each alert


REQUIREMENTS
- Python 3.13.5 +
- scapy
- google-generative.ai
- .pcap file to analyze 

INSTALL REQUIRED PACKAGES 

pip install  scapy google-generativeai 

HOW TO RUN 
make sure your .pcap file is in the same directory 

Open main.py and add your gemini API key to:
genai.configure(api_key="put your api key here")

Run python main.py on the terminal 

Expected results:
- Incident data logged into events.csv
- Alerts in alerts.csv 
- Jira tickets in the console output

THE OUTPUT FILES ARE events.csv and alerts.csv

Google Gemini Pro is the AI tool used 

AUTHOR
Laura Loreto 
