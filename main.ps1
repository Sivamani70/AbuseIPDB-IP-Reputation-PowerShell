[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [String] $FilePath
)

#Remove this . .key.ps1 and Replace the {`$KEY} value with your API-Key - in line 15
. .\key.ps1

class AbuseIPDB {
    static [String] $ENDPOINT = "https://api.abuseipdb.com/api/v2/check"
    static [String] $CSV_FILE_HEADING = "IPAddress, Whitelisted,ISP, AbuseConfidenceScore, Domain, IsTor, UsageType,  CountryCode"
    static [String] $basicPattern = "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    static [Hashtable] $HEADERS = @{
        "key"    = $KEY
        "Accept" = "application/json"
    }
    [String] $FilePath
    [System.Collections.Generic.List[String]] $ipAddresses
    [System.Collections.Generic.List[String]] $responseContent
    [System.Object[]] $content

    AbuseIPDB([String] $FilePath) {
        $this.FilePath = $FilePath
        $this.ipAddresses = New-Object System.Collections.Generic.List[String]
        $this.responseContent = New-Object System.Collections.Generic.List[String]
    }
    
    # Setters
    [void] setContent([string] $file) { $this.content = Get-Content $file }
    [void] addIP([string] $ipAddress) { $this.ipAddresses.Add($ipAddress) }
    [void] addResponse([string] $value) { $this.responseContent.Add($value) }

    # Getters
    [System.Object[]] getContent() { return $this.content }
    [System.Collections.Generic.List[String]] getResponseContent() { return $this.responseContent }
    [System.Collections.Generic.List[String]] getIPs() { return $this.ipAddresses }
    [String] getFilePath() { return $this.FilePath }
}

class CheckIPReputation {

    [AbuseIPDB] $abuseipdb

    CheckIPReputation([AbuseIPDB] $obj) {
        $this.abuseipdb = $obj
    }

    # Checking the file is valid or not
    [bool] isFileValid([String] $filePath) {
        if (!(Test-Path -Path $filePath)) { return $false }
        $this.abuseipdb.setContent($filePath)
        if ($this.abuseipdb.getContent().Length -eq 0) {
            Write-Warning "No data found in the given file"
            return $false
        }
        return $true
    }

    # Extracting IPs from the input file
    [void] ExtractIPs($filePath) {
        Write-Host "Extracting IPS"
        $content = $this.abuseipdb.getContent()
        foreach ($ip in $content) {
            $ip = $ip.Trim()
            if ([System.Text.RegularExpressions.Regex]::IsMatch($ip, [AbuseIPDB]::basicPattern)) {
                $this.abuseipdb.addIP($ip)
            }
        }
    }

    [void] CreateCSVFile([String] $header, [System.Collections.ArrayList] $data) {
        Write-Host "Creating .\out-put.csv file"
        Set-Content -Path ".\out-put.csv" -Value $header
        Add-Content -Path ".\out-put.csv" -Value $data
        $result = Read-Host "Would you like to display the resuluts (Y/N)"
        do {
            if ($result.ToLower().StartsWith('y')) {
                Write-Host "Grid View has opened in a seperate window"
                Import-Csv ".\out-put.csv" | Out-GridView 
                break
            }
            if ($result.ToLower().StartsWith('n')) {
                break
            }
            $result = Read-Host "Would you like to display the resuluts (Y/N)"
        } while (!$result.ToLower().StartsWith('y') -or !$result.ToLower().StartsWith('n'))
        Write-Host "Completed.!" 

    }

    [void] CheckReputation() {           
        # Validating File and Abort Execution
        if (!$this.IsFileValid($this.abuseipdb.getFilePath())) {
            Write-Error "Given File $($this.abuseipdb.getFilePath()) is Invalid/File Not exist"
            return
        }

        # Extracting IPs
        $this.ExtractIPs($this.abuseipdb.getFilePath())
        Write-Host "$($this.abuseipdb.getIPs().Count) - IP(s) found in the file $($this.abuseipdb.getFilePath())"
        
        if ($this.abuseipdb.getIPs().Count -eq 0) { return }
        
        Write-Host "Checking IP reputation..."
        foreach ($ipAddress in $this.abuseipdb.getIPs()) {
            
            [Hashtable] $queryParameters = @{
                "ipAddress" = $ipAddress
            }
                              
            try {
                $response = Invoke-WebRequest -Method Get -Uri $([AbuseIPDB]::ENDPOINT) -Headers $([AbuseIPDB]::HEADERS) -Body $queryParameters

                if ($response.StatusCode -ne 200) {
                    Write-Host "Something went wrong;  Status Code: $($response.StatusCode), Status Description: $($response.StatusDescription)"
                    return;
                }
                $data = ($response.content | ConvertFrom-Json).data

                $this.abuseipdb.addResponse("$($data.ipAddress), $($data.isWhitelisted), $($data.isp), $($data.abuseConfidenceScore),$($data.domain), $($data.isTor), $($data.usageType), $($data.countryCode)")
            }
            catch [System.Net.WebException] {
                Write-Error "Status Code $($_.Exception.Response.StatusCode)"
                Write-Error $($_.Exception.Response)
            }
            catch {
                Write-Error "Something went wrong"
            }
            Write-Host "$($this.abuseipdb.getResponseContent().Count) - IP(s) checked"
        }
        
        if (($this.abuseipdb.getResponseContent().Count) -eq 0) { return }
        Write-Host "Completed Checking $($this.abuseipdb.getResponseContent().Count) - IP(s)"
        $this.CreateCSVFile([AbuseIPDB]::CSV_FILE_HEADING, $this.abuseipdb.getResponseContent())
    }
}

$abuseipdb = [AbuseIPDB]::new($FilePath)
$checkIPReputation = [CheckIPReputation]::new($abuseipdb)
$checkIPReputation.CheckReputation()