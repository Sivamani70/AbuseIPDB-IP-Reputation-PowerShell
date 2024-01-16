[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [String] $APIKEY,
    [Parameter(Mandatory)]
    [String] $FilePath
)

class AbuseIPDB {
    static [String] $ENDPOINT = "https://api.abuseipdb.com/api/v2/check"
    static [String] $IPV4Validator = "^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    static [String] $IPV6Validator = "^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$"
    [Hashtable] $HEADERS = @{}
    [String] $FilePath
    [System.Collections.Generic.List[String]] $ipAddresses
    [System.Collections.Generic.List[PSCustomObject]] $responseObj
    [System.Object[]] $content

    AbuseIPDB([String] $Key, [String] $FilePath) {
        $this.FilePath = $FilePath
        $this.HEADERS.Add("Accept", "application/json")
        $this.HEADERS.Add("key", $Key)
        $this.ipAddresses = New-Object System.Collections.Generic.List[String]
        $this.responseObj = New-Object System.Collections.Generic.List[PSCustomObject]
    }
    
    # Setters
    [void] setContent([string] $file) { $this.content = Get-Content $file }
    [void] addIP([string] $ipAddress) { $this.ipAddresses.Add($ipAddress) }
    [void] addResponse([PSCustomObject] $value) { $this.responseObj.Add($value) }

    # Getters
    [System.Object[]] getContent() { return $this.content }
    [System.Collections.Generic.List[PSCustomObject]] getresponseObj() { return $this.responseObj }
    [System.Collections.Generic.List[String]] getIPs() { return $this.ipAddresses }
    [String] getFilePath() { return $this.FilePath }
    [Hashtable] getHeaders() { return $this.HEADERS }
}

class CheckIPReputation {

    [AbuseIPDB] $abuseipdb

    CheckIPReputation([AbuseIPDB] $obj) {
        Clear-Host
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
            if (($ip -match [AbuseIPDB]::IPV4Validator) -or ($ip -match [AbuseIPDB]::IPV6Validator)) {
                $this.abuseipdb.addIP($ip)
            }
        }
    }

    [void] createCSVFile([System.Collections.Generic.List[PSCustomObject]] $data) {
        Write-Host "Creating .\abuseipdb-out-put.csv file"
        $data | Export-Csv -Path ".\abuseipdb-out-put.csv" -NoTypeInformation
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
                $response = Invoke-WebRequest -Method Get -Uri $([AbuseIPDB]::ENDPOINT) -Headers $this.abuseipdb.getHeaders() -Body $queryParameters

                if ($response.StatusCode -ne 200) {
                    Write-Host "Something went wrong;  Status Code: $($response.StatusCode), Status Description: $($response.StatusDescription)"
                    return;
                }
                $data = ($response.content | ConvertFrom-Json).data

                $obj = [PSCustomObject]@{
                    IPAddress            = $data.ipAddress
                    Whitelisted          = $data.isWhitelisted
                    ISP                  = $data.isp
                    AbuseConfidenceScore = $data.abuseConfidenceScore
                    Domain               = $data.domain
                    IsTor                = $data.isTor
                    UsageType            = $data.usageType
                    CountryCode          = $data.countryCode
                }

                $this.abuseipdb.addResponse($obj)
            }
            catch [System.Net.WebException] {
                Write-Error "Status Code $($_.Exception.Response.StatusCode)"
                Write-Error $($_.Exception.Response)
            }
            catch {
                Write-Error "Something went wrong"
            }
            Write-Host "$($this.abuseipdb.getresponseObj().Count) - IP(s) checked"
        }
        
        if (($this.abuseipdb.getresponseObj().Count) -eq 0) { return }
        Write-Host "Completed Checking $($this.abuseipdb.getresponseObj().Count) - IP(s)"
        $this.createCSVFile($this.abuseipdb.getresponseObj())
    }
}

$abuseipdb = [AbuseIPDB]::new($APIKEY, $FilePath)
$checkIPReputation = [CheckIPReputation]::new($abuseipdb)
$checkIPReputation.CheckReputation()