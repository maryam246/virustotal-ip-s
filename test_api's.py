import requests
import json

# Your VirusTotal API Key
API_KEY = "Enter-your-API-KEY"

# Function to analyze an IP
def analyze_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/analyse"
    headers = {"accept": "application/json", "x-apikey": API_KEY}
    response = requests.post(url, headers=headers)
    return response.json()

# Function to get comments on an IP
def get_comments(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/comments?limit=10"
    headers = {"accept": "application/json", "x-apikey": API_KEY}
    response = requests.get(url, headers=headers)
    return response.json()

# Function to add a comment to an IP
def add_comment(ip, comment_text):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/comments"
    payload = {
        "data": {
            "type": "comment",
            "attributes": {"text": comment_text}
        }
    }
    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY,
        "content-type": "application/json"
    }
    response = requests.post(url, json=payload, headers=headers)
    return response.json()

# Function to get related objects of an IP
def get_related_objects(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/graphs?limit=10"
    headers = {"accept": "application/json", "x-apikey": API_KEY}
    response = requests.get(url, headers=headers)
    return response.json()

# Function to get object descriptors related to an IP
def get_object_descriptors(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/relationships/graphs?limit=10"
    headers = {"accept": "application/json", "x-apikey": API_KEY}
    response = requests.get(url, headers=headers)
    return response.json()

# Function to get votes on an IP
def get_votes(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/votes"
    headers = {"accept": "application/json", "x-apikey": API_KEY}
    response = requests.get(url, headers=headers)
    return response.json()

# Function to add a vote to an IP
def add_vote(ip, verdict):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/votes"
    payload = {
        "data": {
            "type": "vote",
            "attributes": {"verdict": verdict}
        }
    }
    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY,
        "content-type": "application/json"
    }
    response = requests.post(url, json=payload, headers=headers)
    return response.json()

# List of IPs to test
ip_list = ["45.95.11.34", "8.8.8.8"]

# Main loop to call functions for each IP
for ip in ip_list:
    print(f"Processing IP: {ip}")
    
    # Analyze IP
    analysis_response = analyze_ip(ip)
    with open(f"{ip}_analysis.json", "w") as file:
        json.dump(analysis_response, file, indent=4)
    print(f"Analysis for {ip} saved.")

    # Get comments on IP
    comments_response = get_comments(ip)
    with open(f"{ip}_comments.json", "w") as file:
        json.dump(comments_response, file, indent=4)
    print(f"Comments for {ip} saved.")

    # Add a comment to IP
    add_comment(ip, "This IP is under observation.")
    print(f"Comment added for {ip}.")

    # Get related objects of IP
    related_objects_response = get_related_objects(ip)
    with open(f"{ip}_related_objects.json", "w") as file:
        json.dump(related_objects_response, file, indent=4)
    print(f"Related objects for {ip} saved.")

    # Get object descriptors related to IP
    object_descriptors_response = get_object_descriptors(ip)
    with open(f"{ip}_object_descriptors.json", "w") as file:
        json.dump(object_descriptors_response, file, indent=4)
    print(f"Object descriptors for {ip} saved.")

    # Get votes on IP
    votes_response = get_votes(ip)
    with open(f"{ip}_votes.json", "w") as file:
        json.dump(votes_response, file, indent=4)
    print(f"Votes for {ip} saved.")

    # Add a malicious vote to IP
    add_vote(ip, "malicious")
    print(f"Malicious vote added for {ip}.")
