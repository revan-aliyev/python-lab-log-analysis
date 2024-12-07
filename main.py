import re
import json
import csv
from collections import Counter

# Fayl yolları
log_file = "server_logs.txt"
failed_logins_json = "failed_logins.json"
threat_ips_json = "threat_ips.json"
combined_security_data_json = "combined_security_data.json"
log_analysis_txt = "log_analysis.txt"
log_analysis_csv = "log_analysis.csv"

# 1. Log faylından məlumat çıxar
with open(log_file, 'r') as file:
    logs = file.readlines()

ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
date_pattern = r'\[(.*?)\]'
method_pattern = r'\"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)'

ip_counts = Counter()
extracted_data = []

for log in logs:
    ip = re.search(ip_pattern, log).group(1)
    date = re.search(date_pattern, log).group(1)
    method = re.search(method_pattern, log).group(1)
    status_code = log.split('" ')[1].split(' ')[0]
    
    if status_code == "401":  # Uğursuz girişlər
        ip_counts[ip] += 1
    
    extracted_data.append({
        "ip": ip,
        "date": date,
        "method": method,
        "status_code": status_code
    })

# 2. 5-dən çox uğursuz giriş cəhdi olan IP-ləri JSON-a yaz
failed_logins = {ip: count for ip, count in ip_counts.items() if count > 5}
with open(failed_logins_json, 'w') as file:
    json.dump(failed_logins, file, indent=4)

# 3. Təhdid kəşfiyyatı ilə uyğunluq (məsələn, sadə nümunə kimi bəzi IP-lər əlavə edilib)
threat_intel = ["192.168.1.11", "10.0.0.15"]
threat_matches = [ip for ip in threat_intel if ip in ip_counts]
with open(threat_ips_json, 'w') as file:
    json.dump(threat_matches, file, indent=4)

# 4. Uğursuz girişlər və təhdidlər birləşdirilir
combined_data = {
    "failed_logins": failed_logins,
    "threat_matches": threat_matches
}
with open(combined_security_data_json, 'w') as file:
    json.dump(combined_data, file, indent=4)

# 5. Log analizini mətn faylına yaz
with open(log_analysis_txt, 'w') as file:
    for ip, count in ip_counts.items():
        file.write(f"{ip}: {count} failed attempts\n")

# 6. CSV faylı yaradın
with open(log_analysis_csv, 'w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(["IP Address", "Date", "HTTP Method", "Failed Attempts"])
    for data in extracted_data:
        writer.writerow([
            data["ip"], data["date"], data["method"],
            ip_counts[data["ip"]] if data["status_code"] == "401" else 0
        ])
