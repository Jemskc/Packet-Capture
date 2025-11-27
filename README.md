# Intrusion Detection System using Snort-Style Rule Matching & Live Packet Analysis

**Project Overview**

This project implements a lightweight Intrusion Detection System (IDS) capable of real-time packet capture, rule-based analysis, alert generation, and logging.
It supports Snort-style rule parsing, threshold detection, content matching, email alerts, and live traffic monitoring using PyShark.

The system is able to:

Capture packets live from a specified interface

Analyze packets from PCAP files

Parse Snort-like rule structures

Match packets against rule conditions

Detect malicious patterns based on IPs, ports, protocol, content, flow, and thresholds

Store packet metadata inside a SQLite database

Generate alerts into a log file

Send email notifications when rules match


This tool demonstrates how rule-based IDS engines operate internally.


**Features**
1. Snort-Style Rule Parsing

Supports full rule structure, including:

Protocol

Source / Destination IP

Ports

Direction (->, <-, <>, any)

Options: content, msg, flow, threshold

Additional capabilities:

Extracts all option key-value pairs

Supports ASCII and Hex content patterns (|AA BB CC|)


2. Live Packet Capture

Uses PyShark for real-time capture:

Protocol filtering

Continuous monitoring

Packet count limits

Save captured traffic to PCAP file


3. PCAP File Analysis

Analyze offline packet capture:

python script.py -o file.pcap



4. Alerting System

Alerts triggered for matches on:

Protocol

Direction

IP / Port

Payload content

Flow rules

Threshold rules

Alert delivery channels:

Console output

alert.log

Email notification (SMTP)


5. SQLite Logging

Each packet is saved with:

Timestamp

Protocol

Source IP / Port

Destination IP / Port

Stored in packets.db for future review.


**Requirements**

Dependency	Purpose
Python 3.x	Main runtime
PyShark	Packet capture
Tshark	Backend for PyShark
SQLite3	Database logging
psutil	System utilities
smtplib	Email alerts
re/json/os/sys/time	Utility libs


**Install dependencies:
**

pip install pyshark psutil


**Install Tshark (required for PyShark):
**
sudo apt-get install tshark


**Usage**

1. Live Packet Capture

Capture from interface:

python script.py -i eth0


Only capture TCP packets:

python script.py -i eth0 -p tcp


Save captured packets:

python script.py -i wlan0 -s captured.pcap


Capture limited number of packets:

python script.py -i eth0 -n 50


Verbose mode:

python script.py -i eth0 -v



**2. Analyze a PCAP File
**

python script.py -o sample.pcap



3. Snort Rules Configuration

Place rules inside:

snort_rules.conf

Example rule:

alert tcp any any -> 192.168.1.10 80 (msg:"Possible Attack"; content:"GET"; threshold:type both, track by_src, count 5, seconds 10;)


**Output Files
**
1. alert.log

Stores all generated alerts.


2. packets.db

SQLite database of all captured packets.


3. Console Output


Displays:

Time

Protocol

Source → Destination

Ports


Email Alerting

Uses Gmail SMTP.

Set credentials:

email_address = 'your_email@gmail.com'
email_password = 'your_generated_app_password'


Enable App Passwords in Google Account if using 2FA.


Program Flow Summary

Parse Snort rules

Start packet capture (live or PCAP)

Extract protocol, ports, IPs, payload

Compare packet to rule conditions

**Evaluate**:

Protocol match

Direction match

IP/Port match

Payload content

Threshold and flow

Generate alerts

Save packet metadata in database

Send email alerts as needed


**Future Enhancements
**
GUI dashboard

Multi-threading for high-speed networks

Automated signature/rule updating

Integrate machine learning anomaly detection


**Disclaimer**

This project is for educational and research purposes only.
Packet capturing without authorization is illegal in many jurisdictions.





