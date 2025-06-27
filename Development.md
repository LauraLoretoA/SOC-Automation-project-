PROJECT TOOLS AND STACK 
 This project focuses on utomation principles emphasizing accessinility and clarity 

 Development Environment 
 - Operating System: Windows 11
 - IDE: VS Code 
 - Language: Python 3.13

 Core Python Libraries
 scapy - used for parsing the pcap file
 csv - used in logging the output to the .csv files
 datetime - for timestamps
 os - for file path and handling 

 Automation 
 google-generativeai - Used to access Google Gemini Pro
 Gemini Pro Model - AI Model used in incident analysis 

 STRUCTURE OF THE FOLDER
 Serianu/
 |-- alerts.csv       #AI-analyzed alerts
 |-- Development.md   #Tools and tech stack 
 |-- events.csv       #detailed logs
 |-- get-pip.py       #pip activator
 |-- listmodels.py    #list of available gemini pro models
 |-- main.py          # Main Script
 |-- README.md        #Project Overvie and Instructions
 |-- sample_http.cap  #Test PCAP file
 |-- flowchart.png    # SOC vs automation diagram

 Gemini Ai was used to automate the analysis of incidents and emulate real world events 
 Due to the simulation of Jira tickets I hope to enhance the Jira API integration in the future with real credentials 
