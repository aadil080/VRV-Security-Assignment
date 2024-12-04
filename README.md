### Assignment: Log Analysis Script  

#### **Objective**  
The assignment involves writing a Python script to analyze log files, extracting key information to identify patterns, potential issues, and anomalies. This task evaluates your skills in file handling, string manipulation, data analysis, and command-line tools.

#### **Core Requirements**  
1. **Count Requests per IP Address**:  
   - Parse the log file to count requests made by each IP.  
   - Display results in descending order of request counts.

2. **Identify Most Accessed Endpoint**:  
   - Extract the most frequently accessed resource or URL.  
   - Display the endpoint name and access count.

3. **Detect Suspicious Activity**:  
   - Identify potential brute-force attempts by finding failed login logs (e.g., HTTP 401 errors or "Invalid credentials").  
   - Flag IPs with failed attempts exceeding a threshold (default: 10).

4. **Output Results**:  
   - Displaying results in the terminal.  
   - Saving data in a well-formatted CSV file containing:
     - IP request counts  
     - Most accessed endpoint  
     - Suspicious IPs and failed login counts  

#### **Skills Evaluated**  
- Python scripting and automation.  
- File parsing and string processing.  
- Data organization and analysis.  
- Command-line argument handling with optional defaults (`argparse`).  

#### Arguments Added
* "-lf" and "--logfile" : Path to the log file (default: sample.log).
*  "-th" and "--threshold" : Threshold for suspicious activity detection (default: 10).  
* "-op" and "--output" : Output file for storing the results of parsing  (default: log_analysis_results.csv).
 
This assignment simulates real-world log analysis scenarios, such as identifying suspicious activities or optimizing system performance.