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
        foreach ($ioc in $content) {
            $ioc = $ioc.Trim()
            if (($ioc -match [AbuseIPDB]::IPV4Validator) -or 
                ($ioc -match [AbuseIPDB]::IPV6Validator)) {
                $this.abuseipdb.addIP($ioc)
            }
        }
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
        foreach ($ip in $this.abuseipdb.getIPs()) {

            [Hashtable] $queryParameters = @{
                "ipAddress" = $ip
                "verbose"   = " "
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
                    ISP                  = $data.isp
                    TotalReports         = $data.totalReports
                    AbuseConfidenceScore = $data.abuseConfidenceScore
                    Domain               = $data.domain
                    Whitelisted          = $data.isWhitelisted
                    IsTor                = $data.isTor
                    UsageType            = $data.usageType
                    CountryCode          = $data.countryCode
                    CountryName          = $data.countryName
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


        # Checking Excel is installed or not
        if (!(Test-Path -Path HKLM:\SOFTWARE\Microsoft\Office\*\Excel\)) {
            Write-Host "Excel Application not found"
            Write-Host "Creating CSV File"
            $this.createCSVFile($this.abuseipdb.getresponseObj())        
        }
        else {
            Write-Host "Excel Application found"
            $this.createXLFile($this.abuseipdb.getresponseObj())
        }

    }


    [String] getFileName() {
        [DateTime] $dateTime = Get-Date
        [String] $timeStamp = "$($dateTime.DateTime)"
        return "Abuseipdb-Out-File - $timeStamp"
    }

    [void] createCSVFile([System.Collections.Generic.List[PSCustomObject]] $data) {
        [String] $fileName = $this.getFileName()
        Write-Host "Creating .\$fileName.csv file"
        $data | Export-Csv -Path ".\$fileName.csv" -NoTypeInformation
        Write-Host "Completed creating $fileName.csv file"    
    }


    [void] createXLFile([System.Collections.Generic.List[PSCustomObject]] $data) {
        $excel = New-Object -ComObject Excel.Application
        [String] $fileName = $this.getFileName()
        try {
            $workBook = $excel.Workbooks.Add()
            $sheet = $workBook.Worksheets.Item(1)
            $sheet.Name = "IPs Rep"
        
            $row = 1
            $sheet.Cells.Item($row, 1) = "IPAddress"
            $sheet.Cells.Item($row, 2) = "ISP"
            $sheet.Cells.Item($row, 3) = "TotalReports"
            $sheet.Cells.Item($row, 4) = "AbuseConfidenceScore"
            $sheet.Cells.Item($row, 5) = "Domain"
            $sheet.Cells.Item($row, 6) = "Whitelisted"
            $sheet.Cells.Item($row, 7) = "IsTor"
            $sheet.Cells.Item($row, 8) = "UsageType"
            $sheet.Cells.Item($row, 9) = "CountryCode"
            $sheet.Cells.Item($row, 10) = "CountryName"

            $row = 2

            forEach ($obj in $data) {
                $sheet.Cells.Item($row, 1) = $obj.IPAddress
                $sheet.Cells.Item($row, 2) = $obj.ISP
                $sheet.Cells.Item($row, 3) = $obj.TotalReports
                $sheet.Cells.Item($row, 4) = $obj.AbuseConfidenceScore
                $sheet.Cells.Item($row, 5) = $obj.Domain
                $sheet.Cells.Item($row, 6) = $obj.Whitelisted
                $sheet.Cells.Item($row, 7) = $obj.IsTor
                $sheet.Cells.Item($row, 8) = $obj.UsageType
                $sheet.Cells.Item($row, 9) = $obj.CountryCode
                $sheet.Cells.Item($row, 10) = $obj.CountryName
                $row++
            }
            Write-Host "Creating $fileName.xlsx file"
            $currentPath = Get-Location
            $completePath = $currentPath.Path + "\$fileName.xlsx"  
            $workBook.SaveAs($completePath)
            $workbook.Close()
            $excel.Quit()
            Write-Host "Completed creating $fileName.xlsx file"
        }
        finally {
            [int] $exitCode = [System.Runtime.InteropServices.Marshal]::ReleaseComObject($excel)
            Write-Host "Closed Excel App with status code $exitCode"
        }
    }   
}

$abuseipdb = [AbuseIPDB]::new($APIKEY, $FilePath)
$checkIPReputation = [CheckIPReputation]::new($abuseipdb)
$checkIPReputation.CheckReputation()