from datetime import datetime
from scapy.all import rdpcap, IP, TCP, Ether, DNS, DNSQR, Raw
import google.generativeai as genai
import csv
import os
import re  


#ai configuration
genai.configure(api_key="AIzaSyC47sA9mCF-b4oHbPDeorjNNmLZ6gh6FTA")

   
   # describe function
def describe(incident):
       
       desc = f"Traffic from {incident.get('src')} to {incident.get('dst')}"
     
       if incident.get("sport") and incident.get("dport"):
        desc += f"It used port{incident['sport']} to {incident['dport']}."

       if incident.get("url"):
         desc += f"The requested URL was {incident['url']}."

       if incident.get("agent"): 
        desc += f"The User-Agentstring was {incident['agent']}."
 
       if incident.get("host"):
        desc += f"It resolved the host{incident['host']}."
  
       
       return desc.strip()

   
   # incident analysis function
def incident_analysis(incident_description):
    prompt = f"""Assume you are a cybersecurity analyst 
    Analyze this incident carefully and return 
    - The Incident Name
    - Criticality (High, Medium or Low)
    - Confidence score (0-1)
    -  MITRE Tactics and techniques
    -  Remedies 

    INCIDENT :
    {incident_description}
    """
    try:
        model = genai.GenerativeModel("models/gemini-1.5-flash")
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"Gemini API error: {e}"
    
   
   
    # Defining the logs 
def init_csv_log(filename):
        if not os.path.exists(filename):
            with open(filename, mode='w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(["timestamp","src", "dst", "sport", "dport", "host", "url", "agent", "client_mac"])
                 
def init_alert_log(filename):
        if not os.path.exists(filename):
            with open(filename, mode='w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(["timestamp", "incident_name", "criticality", "confidence"])
   
    
    # Parsing alert fields
def extract_alert_fields(analysis_text):
    name = criticality = confidence = "Unknown"

    if match := re.search(r"(?i)incident name\s*[:\-]\s*(.+)", analysis_text):
        name = match.group(1).strip()
    if match := re.search(r"(?i)criticality\s*[:\-]\s*(High|Medium|Low)", analysis_text):
        criticality = match.group(1).strip()
    if match := re.search(r"(?i)confidence score\s*[:\-]?\s*(0-9.)", analysis_text):
        confidence = match.group(1).strip()
       
    return name, criticality, confidence
   
   
    # Jira Ticket Creation -Simulated due to lack of usale credentials that would work seamlessly with the code 
def create_jira_ticket(name, criticality, confidence):
    summary = f"[{criticality}] {name} (Confidence: {confidence})"
    description = (
        f"Auto-generated alert:\n"
        f"- Name: {name}\n"
        f"- Criticality: {criticality}\n"
        f"- Confidence: {confidence}\n"
    )
    print("Jira Ticket:")
    print("Summary:", summary)
    print("Description:\n", description)



    # Main Parsing 
def parse_pcap(filepath):
    incidents = []
    packets = rdpcap(filepath)
    print(f"Total packets loaded: {len(packets)}")

    log_file = "events_csv"
    alert_log = "alerts_csv"
    init_csv_log(log_file)
    init_alert_log(alert_log)
    
    for pkt in packets:
        incident = {}

        if pkt.haslayer(Ether):
            incident["client_mac"] = pkt[Ether].src

        if pkt.haslayer(IP):
              incident["src"], incident["dst"] = pkt[IP].src, pkt[IP].dst
                 
        if pkt.haslayer(TCP): 
         incident["sport"], incident["dport"] = pkt[TCP].sport, pkt[TCP].dport       
         
         if pkt.haslayer(DNSQR):
           incident ["host"] = pkt[DNSQR].qname.decode(errors="ignore")            
        if pkt.haslayer(Raw):
            try:
                data = pkt[Raw].load.decode(errors="ignore")
                if "User-Agent" in data or "Host:" in data:
                        for line in data.splitlines():
                         if "User-Agent" in line: incident["agent"] = line.strip()
                        if "Host:" in line: incident["url"] = line.split("Host:")[-1].strip()
            except Exception as e: 
              print(f"Error decoding Raw layer: {e}")
              pass 
        
    if incident:
          print("\n Captured Incident:", incident)
          
          for key, value in incident.items():
                
             print(f"{key}: {value}")

    desc = describe(incident)
    print("\n Description:", desc)
    print("\n Gemini Analysis:")
    analysis = incident_analysis(desc)
    print(analysis)

    # Log event 
    with open(log_file, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([
            datetime.utcnow().isoformat() + "z",
            incident.get("src", ""),
            incident.get("dst", ""),
            incident.get("sport", ""),
            incident.get("dport", ""),
            incident.get("host", ""),
            incident.get("url", ""),
            incident.get("agent", ""),
            incident.get("client_mac", ""),
            
        ])
    
    # Log alert
    incident_name, criticality, confidence = extract_alert_fields(analysis)
    print("Extracted", incident_name, criticality, confidence)
    with open(alert_log, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([
          datetime.utcnow().isoformat() + "z",
          incident_name,
          criticality,
          confidence

          ])
    # Jira Ticket now 
    create_jira_ticket(incident_name, criticality, confidence)

    
    incidents.append(incident)

    return incidents
       
       
parse_pcap("sample_http.pcap")
                
            
        
