[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [String] $FilePath
)

#Remove this . .key.ps1 and Replace the {`$KEY} value with your API-Key
. .\key.ps1

class AbuseIPDB {
    static [String] $ENDPOINT = "https://api.abuseipdb.com/api/v2/check"
    static [String] $CSV_FILE_HEADING = "IPAddress, Whitelisted,ISP, AbuseConfidenceScore, Domain, IsTor, UsageType,  CountryCode"
    static [String] $basicPatteren = "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    static [Hashtable] $HEADERS = @{
        "key"    = $KEY
        "Accept" = "application/json"
    }
    [String] $FilePath
    [System.Collections.ArrayList] $listOfIPs
    [System.Collections.ArrayList] $responseData
    [System.Object[]] $content

    AbuseIPDB([String] $FilePath) {
        $this.FilePath = $FilePath
        $this.listOfIPS = New-Object System.Collections.ArrayList<String>
        $this.responseData = New-Object System.Collections.ArrayList<String>
    }
    
    # Setters
    [void] setContent([string] $file) { $this.content = Get-Content $file }
    [void] addIP([string] $ipAddress) { $this.listOfIPs.Add($ipAddress) }
    [void] addResponse([string] $value) { $this.responseData.Add($value) }

    # Getters
    [System.Object[]] getContent() { return $this.content }
    [System.Collections.ArrayList] getResponseData() { return $this.responseData }
    [System.Collections.ArrayList] getIPs() { return $this.listOfIPs }
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
            if ([System.Text.RegularExpressions.Regex]::IsMatch($ip, [AbuseIPDB]::basicPatteren)) {
                $this.abuseipdb.addIP($ip)
            }
        }
    }

    [void] CreateCSVFile([String] $header, [System.Collections.ArrayList] $data) {
        Write-Host "Creating .\out-put.csv file"
        Set-Content -Path ".\out-put.csv" -Value $header
        Add-Content -Path ".\out-put.csv" -Value $data
        $result = Read-Host "Would you like to display the resuluts (Y/N): "
        do {
            if ($result.ToLower().chars(0) -eq 'y') {
                Write-Host "Grid View has opened in a seperate window"
                Import-Csv ".\out-put.csv" | Out-GridView 
                break
            }
            if ($result.ToLower().chars(0) -eq 'n') {
                break
            }
            $result = Read-Host "Would you like to display the results (Y/N)"
        } while ($result.ToLower().chars(0) -ne 'y' -or $result.ToLower().chars(0) -ne 'n')
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
            Write-Host "$($this.abuseipdb.getResponseData().Count) - IP(s) checked"
        }
        
        if (($this.abuseipdb.getResponseData().Count) -eq 0) { return }
        Write-Host "Completed Checking $($this.abuseipdb.getResponseData().Count) - IP(s)"
        $this.CreateCSVFile([AbuseIPDB]::CSV_FILE_HEADING, $this.abuseipdb.getResponseData())
    }
}

$abuseipdb = [AbuseIPDB]::new($FilePath)
$checkIPReputation = [CheckIPReputation]::new($abuseipdb)
$checkIPReputation.CheckReputation()