from tabulate import tabulate
import csv

def getAllIpRequestCount(ip_logs):
    iP_request_count = dict()
    for log in ip_logs:
        iP_request_count[log[0]] = iP_request_count.get(log[0], 0) + 1
    sorted_ip_by_value = sorted(iP_request_count.items(), key=lambda item: item[1], reverse=True)
    return sorted_ip_by_value

def printAllIpRequestCount(each_ip_request_count):
    headers = ["IP Address", "Request Count"]
    print(tabulate(each_ip_request_count, headers=headers, tablefmt="plain", colalign=("center", "center")))
    print()

def getEachAccessEndpointCount(ip_logs):
    each_access_endpoint_count = dict()
    for log in ip_logs:
        for value in log:
            if value.startswith("/"):
                each_access_endpoint_count[value] = each_access_endpoint_count.get(value, 0) + 1
    return each_access_endpoint_count

def printMostFrequentlyUsedAccessEndPoint(each_access_endpoint_count):
    most_used_access_path = max(each_access_endpoint_count.items(), key=lambda item: item[1])
    print("Most Frequently Accessed Endpoint:")
    print(f"{most_used_access_path[0]} (Accessed {most_used_access_path[1]} times)")
    print()
    return [[most_used_access_path[0], most_used_access_path[1]]]

def getAllSuspiciousIPs(ip_logs):
    invalid_ips = dict()
    for log in ip_logs:
        ip = log[0]
        if log[-2][1:].startswith("Invalid") or log[-2] == "401":
            invalid_ips[ip] = invalid_ips.get(ip, 0) + 1
    
    suspicious_ips = dict()
    minimum_flagging_threshold = 10
    for ip,invalid_ip_count in invalid_ips.items():
        if invalid_ip_count > minimum_flagging_threshold:
            suspicious_ips[ip] = invalid_ip_count
    return suspicious_ips

def printAllSuspiciousIp(suspicious_ips):
    print("Suspicious Activity Detected:")
    headers = ["IP Address", "Failed Login Attempts"]
    print(tabulate(suspicious_ips.items(), headers=headers, tablefmt="plain", colalign=("center", "center")))

def saveAllDataInCsvFile(each_ip_request_count, most_used_access_path, suspicious_ips):
    filename = "log_analysis_results.csv"
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        
        # 1: Requests per IP
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(each_ip_request_count)
        writer.writerow([])
        
        # 2: Most Accessed Endpoint
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerows(most_used_access_path)
        writer.writerow([])
        
        # 3: Suspicious Activity
        writer.writerow(["IP Address", "Failed Login Count"])
        writer.writerows(suspicious_ips.items())


if __name__=="__main__":
    ip_log_file = open("sample.log", "r")

    ip_logs = []
    for log in ip_log_file:
        ip_logs.append(log.split(" "))

    # 1. Count Requests per IP Address:
    each_ip_request_count = getAllIpRequestCount(ip_logs)
    printAllIpRequestCount(each_ip_request_count)

    # 2. Identify the Most Frequently Accessed Endpoint:
    each_access_endpoint_count = getEachAccessEndpointCount(ip_logs)
    most_used_access_path = printMostFrequentlyUsedAccessEndPoint(each_access_endpoint_count)

    #3. Detect Suspicious Activity:
    suspicious_ips = getAllSuspiciousIPs(ip_logs)
    printAllSuspiciousIp(suspicious_ips)

    #4. Output Results in CSV file
    saveAllDataInCsvFile(each_ip_request_count, most_used_access_path, suspicious_ips)