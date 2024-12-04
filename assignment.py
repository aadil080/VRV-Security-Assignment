import argparse


def parsing_log_file(logfile):
    '''
    This function parses the log file and outputs the data needed.

    Inputs:
    file_path: string = This provides the filepath of the file

    Outputs:
    Evaluated data of IP address, endpionts, status code and failed requests is stored directly on the global variables.
    
    '''
    # Opening and reading the log file 
    with open(logfile, "r") as file:
        for line in file:
            # Parsing the file line by line to extract IP address, endpoint, status code, and message
            parts = line.split()
            ip = parts[0]
            endpoint = parts[6]
            status_code = parts[8]
            message = " ".join(parts[9:]) if len(parts) > 9 else ""

            # Counting all requests per IP address
            if ip in ip_request_counts:
                ip_request_counts[ip] += 1
            else:
                ip_request_counts[ip] = 1

            # Counting endpoint access attempts
            if endpoint in endpoint_access_counts:
                endpoint_access_counts[endpoint] += 1
            else:
                endpoint_access_counts[endpoint] = 1

            # Here this counts failed login attempts
            if status_code == "401" and "Invalid credentials" in message:
                if ip in failed_login_attempts:
                    failed_login_attempts[ip] += 1
                else:
                    failed_login_attempts[ip] = 1

def display():
    '''
    This function displays all the fetched results from the log file.

    Inputs:
    No input required. It uses global variables to display the results.

    Outputs:
    Result of the fetching and evaluation of the log file.  

    '''
    # Displaying all the fetched results
    print("IP Address           Request Count")
    print("-" * 34)
    for ip, count in sorted_ip_requests:
        print(f"{ip:<20} {count}") # Left skewed for better terminal output
    
    print("\nMost Frequently Accessed Endpoint:")
    most_accessed_endpoint, access_count = sorted_endpoint_accesses[0]
    print(f"{most_accessed_endpoint} (Accessed {access_count} times)")
    
    print("\nSuspicious Activity Detected:")
    if suspicious_ips:
        print("IP Address           Failed Login Attempts")
        print("-" * 34)
        for ip, count in suspicious_ips:
            print(f"{ip:<20} {count}")
    else:
        print("No suspicious activity detected.")

def saving_results(save_file_path):
    '''
    This function saves the result to the provided "save_file_path".

    Inputs:
    "save_file_path" required to name the file path.

    Outputs:
    Result of the fetching and evaluation of the log file into a .csv file.

    '''
    # Saving all fetched results to a CSV file manually called "save_file_path"
    with open(save_file_path, "w") as file:
        # Write requests per IP
        file.write("Requests per IP\n")
        file.write("IP Address,Request Count\n")
        for ip, count in sorted_ip_requests:
            file.write(f"{ip},{count}\n")
    
        # Write most accessed endpoint
        most_accessed_endpoint, access_count = sorted_endpoint_accesses[0]
        file.write("\nMost Accessed Endpoint\n")
        file.write("Endpoint,Access Count\n")
        file.write(f"{most_accessed_endpoint},{access_count}\n")
    
        # Write suspicious activity
        file.write("\nSuspicious Activity\n")
        file.write("IP Address,Failed Login Count\n")
        for ip, count in suspicious_ips:
            file.write(f"{ip},{count}\n")


if __name__ == "__main__":

    parser = argparse.ArgumentParser()

    # Add arguments with default values
    parser.add_argument(
        "-lf",
        "--logfile", 
        type=str, 
        default="sample.log", 
        help="Path to the log file (default: sample.log)"
    )

    parser.add_argument(
        "-th",
        "--threshold", 
        type=int, 
        default=10, 
        help="Threshold for suspicious activity detection (default: 10)"
    )

    parser.add_argument(
        "-op",
        "--output", 
        type=str, 
        default="log_analysis_results.csv", 
        help="Output file for storing the results of parsing (default: log_analysis_results.csv)"
    )

    # Parse arguments
    args = parser.parse_args()

    # Access the arguments
    logfile = args.logfile
    threshold = args.threshold
    output_file = args.output

    print(f"Log file: {logfile}")
    print(f"Threshold: {threshold}")
    
    # Configurable threshold for detecting suspicious activity
    FAILED_LOGIN_THRESHOLD = threshold

    # Initialize dictionaries for analysis
    ip_request_counts = {}
    endpoint_access_counts = {}
    failed_login_attempts = {}

    # Parsing the log file
    parsing_log_file(logfile)
    
    # Sorting the results
    sorted_ip_requests = sorted(ip_request_counts.items(), key=lambda x: x[1], reverse=True)
    sorted_endpoint_accesses = sorted(endpoint_access_counts.items(), key=lambda x: x[1], reverse=True)
    suspicious_ips = [(ip, count) for ip, count in failed_login_attempts.items() if count > FAILED_LOGIN_THRESHOLD]

    # Saving all the results to the "output_file"
    saving_results(output_file)

    # Displaying all the results into the terminal.
    display()