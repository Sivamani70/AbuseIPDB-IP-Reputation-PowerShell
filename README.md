# Bulk IP Reputation with AbuseIPDB - PowerShell Script

### Note: Remove the line `. .\key.ps1` from script `main.ps1`

### Replace `$KEY` with your API Key from AbuseIPDB in `main.ps1`

```powershell
    static [Hashtable] $HEADERS = @{
        "key"    = $KEY
        "Accept" = "application/json"
    }
```

## Script Functionality

### IP Extraction and Validation:

- Parses the given input file to extract IP addresses. Verifies the extracted IP address [As of now only using basic parsing for IPV4 will add support for IPV6].

### Reputation Assessment:

- Queries a reputable IP reputation service for each valid IP address.
- Gathers comprehensive reputation data such as
  - IPAddress,
  - Whitelisted,
  - ISP,
  - AbuseConfidenceScore,
  - Domain,
  - IsTor,
  - UsageType,
  - CountryCode

### Data Export:

- Organizes the collected IP addresses and their associated reputation information into a structured format.
- Generates a CSV file named "out-put.csv" within the same directory as the main.ps1 script to store the results.

## Instructions for running the script

> _Step1:_

1.  Change Windows execution policies to run scripts downloaded from the internet
2.  Open PowerShell as Administrator
3.  Check the current execution policy
    - Type `Get-ExecutionPolicy` and press Enter. This will usually display "`Restricted`" by default.
4.  Change the execution policy
    - To allow running scripts downloaded from the internet, type
    - `Set-ExecutionPolicy RemoteSigned` Press Enter and confirm the change by typing "Y".
5.  Read more about [ExecutionPolicies](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-5.1)

> _Step2:_

- Run the below command  
  `.\main.ps1 -FilePath "file_name with the IPs"`
- **_-FilePath_**: takes the path of the file contains the IPs  
   `'.txt' file with each IP seperated by new line`

> `Ex: .\main.ps1 -FilePath .\malicious-ips.txt`

### Simpler way

---

- Run command `powershell.exe -ExecutionPolicy ByPass -File .\main.ps1 -FilePath "file_name with the IPs"`
- -ExecutionPolicy Bypass: parameter tells PowerShell to temporarily bypass its default execution policy for this specific command.
- By using "Bypass," you're instructing PowerShell to ignore any restrictions and run the script, even if it wouldn't normally be allowed.
- The command essentially says, "Run the script named main.ps1, and while you're at it, ignore any execution policy restrictions that might normally prevent it from running."

> `Ex: powershell.exe -ExecutionPolicy ByPass -File .\main.ps1 -FilePath .\malicious-ips.txt`

<br />
