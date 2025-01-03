# VirusTotal IP Address Methods Documentation

## **1. Analyze an IP Address (POST Method)**

### **Endpoint:**  
`https://www.virustotal.com/api/v3/ip_addresses/{ip}/analyse`

### **Description:**  
This method requests VirusTotal to analyze the given IP address and update the data. It does not directly return the analysis results but ensures the latest analysis is available.  

### **Use Case:**  
If you suspect an IP address has recently engaged in malicious activities (e.g., phishing), you can use this method to request a fresh scan of the IP.

---

## **2. Get Comments on an IP Address (GET Method)**

### **Endpoint:**  
`https://www.virustotal.com/api/v3/ip_addresses/{ip}/comments?limit=10`

### **Description:**  
Retrieves comments made by the community on the specified IP address. These comments provide insights into the reputation of the IP (e.g., safe or malicious).  

### **Use Case:**  
To understand the perception of a suspicious IP within the cybersecurity community, such as identifying whether it's involved in malware distribution or other threats.

---

## **3. Add a Comment to an IP Address (POST Method)**

### **Endpoint:**  
`https://www.virustotal.com/api/v3/ip_addresses/{ip}/comments`

### **Description:**  
Allows users to add their own comments or observations about a specific IP address.  

### **Use Case:**  
If you've analyzed an IP and found it to be spammy or safe, you can leave a note for others, like “This IP is safe” or “Avoid this IP.”

---

## **4. Get Related Objects of an IP Address (GET Method)**

### **Endpoint:**  
`https://www.virustotal.com/api/v3/ip_addresses/{ip}/graphs?limit=10`

### **Description:**  
Fetches objects (e.g., domains, files, or URLs) related to the specified IP address.  

### **Use Case:**  
If an IP address is linked to a malware file or suspicious domain, you can investigate these connections for deeper insights.

---

## **5. Get Object Descriptors Related to an IP Address (GET Method)**

### **Endpoint:**  
`https://www.virustotal.com/api/v3/ip_addresses/{ip}/relationships/graphs?limit=10`

### **Description:**  
Provides metadata or descriptors of objects related to the IP address, explaining their purpose and relationships.  

### **Use Case:**  
To determine how an IP is linked to unknown domains or files and whether they are safe or malicious.

---

## **6. Get Votes on an IP Address (GET Method)**

### **Endpoint:**  
`https://www.virustotal.com/api/v3/ip_addresses/{ip}/votes`

### **Description:**  
Retrieves votes cast by the community on whether an IP is `safe` or `malicious`.  

### **Use Case:**  
If an IP has more malicious votes, it indicates that the community perceives it as a threat. Conversely, a majority of safe votes suggest trustworthiness.

---

## **7. Add a Vote to an IP Address (POST Method)**

### **Endpoint:**  
`https://www.virustotal.com/api/v3/ip_addresses/{ip}/votes`

### **Description:**  
Allows you to cast your vote for an IP address as either `safe` or `malicious`.  

### **Use Case:**  
After analyzing an IP address, you can vote to help others understand its nature, such as marking it as safe if it is trustworthy or malicious if it poses a threat.

---

## **8. Get an IP Address Report (GET Method)**

### **Endpoint:**  
`https://www.virustotal.com/api/v3/ip_addresses/{ip}`

### **Description:**  
Retrieves a detailed report of the specified IP address, including its history, resolutions, detected URLs, and more.  

### **Use Case:**  
To comprehensively analyze an IP address’s past and present behavior, determine its reputation, and identify its potential for malicious activities.

---

## **Real-Life Scenario:**  

Imagine you receive an unknown IP address from a suspicious email:  
1. **Analyze IP:** Request a scan to check for recent activity.  
2. **Get Comments:** See what the community has to say about the IP.  
3. **Get Related Objects:** Investigate domains or files associated with the IP.  
4. **Get Votes:** Analyze whether the community believes the IP is safe or malicious.  
5. **Add Vote/Comment:** If the IP is found to be harmful, cast a vote or leave a comment to warn others.  

Using these methods, you can thoroughly understand and manage the behavior and reputation of an IP address.

--- 

### **Note:**  
Replace `{ip}` in the endpoints with the actual IP address you wish to investigate, Also ENTER the API_KEY. Always ensure that you have a valid VirusTotal API key to use these endpoints.
