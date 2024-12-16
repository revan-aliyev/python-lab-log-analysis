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

# Log faylını oxuma funksiyası
def read_logs(file_path):
    with open(file_path, 'r') as file:
        return file.readlines()

# Regex vasitəsilə məlumat çıxarma funksiyası
def extract_data(logs):
    ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    date_pattern = r'\[(.*?)\]'
    method_pattern = r'\"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)'

    extracted_data = []
    ip_counts = Counter()

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

    return extracted_data, ip_counts

# JSON faylına yazma funksiyası
def write_json(file_path, data):
    with open(file_path, 'w') as file:
        json.dump(data, file, indent=4)

# Mətn faylına yazma funksiyası
def write_text(file_path, data):
    with open(file_path, 'w') as file:
        for ip, count in data.items():
            file.write(f"{ip}: {count} failed attempts\n")

# CSV faylına yazma funksiyası
def write_csv(file_path, data, ip_counts):
    with open(file_path, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["IP Address", "Date", "HTTP Method", "Failed Attempts"])
        for entry in data:
            writer.writerow([
                entry["ip"], entry["date"], entry["method"],
                ip_counts[entry["ip"]] if entry["status_code"] == "401" else 0
            ])

# Log faylını oxu
logs = read_logs(log_file)

# Məlumat çıxar
extracted_data, ip_counts = extract_data(logs)

# 3-dən çox uğursuz giriş cəhdi olan IP-ləri JSON-a yaz
failed_logins = {ip: count for ip, count in ip_counts.items() if count > 3}
write_json(failed_logins_json, failed_logins)

# Təhdid kəşfiyyatı ilə uyğunluq 
threat_intel = ["192.168.1.11", "10.0.0.15", "172.138.43.58", "86.124.105,68"]
threat_matches = [ip for ip in threat_intel if ip in ip_counts]
write_json(threat_ips_json, threat_matches)

# Uğursuz girişlər və təhdidlər birləşdirilir
combined_failed_logins = {ip: count for ip, count in ip_counts.items() if count > 0}
combined_data = {
    "failed_logins": combined_failed_logins,
    "threat_matches": threat_matches
}
write_json(combined_security_data_json, combined_data)

# Log analizini mətn faylına yaz
write_text(log_analysis_txt, ip_counts)

# CSV faylı yaradın
write_csv(log_analysis_csv, extracted_data, ip_counts)
