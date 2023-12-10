[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]
    $FilePath
)

#Remove this . .key.ps1 and Replace the {`$KEY} value with your API-Key
. .\key.ps1

if (!(Test-Path $FilePath)) {
    Write-Error "$FilePath is not found in the current location"
    return
}

# Constant - Values
$ENDPOINT = "https://api.abuseipdb.com/api/v2/check"
$HEADERS = @{
    "key"    = $KEY
    "Accept" = "application/json"
}
# Header for the CSV file
$CSV_FILE_HEADING = "IPAddress, Whitelisted,ISP, AbuseConfidenceScore, Domain, IsTor, UsageType,  CountryCode"

$listOfIPs = New-Object System.Collections.ArrayList
$responseData = New-Object System.Collections.ArrayList
$basicPatteren = "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
$content = Get-Content -Path $FilePath

if ($content.Length -eq 0) {
    Write-Warning "No data found in the given file"
    return
}

foreach ($ip in $content) {
    $ip = $ip.Trim()
    if ([System.Text.RegularExpressions.Regex]::IsMatch($ip, $basicPatteren)) {
        $listOfIPS.Add($ip) | Out-Null
    }
}

Write-Output "$($listOfIPs.Count) - IPs found in the file $FilePath"
if ($listOfIPs.Count -eq 0) { return }
Write-Output "Checking IPs reputation"

foreach ($ipaddress in $listOfIPs) {
    # URL parameters
    $queryParameters = @{
        "ipAddress" = $ipaddress
    }
    try {
        $response = Invoke-WebRequest -Uri $ENDPOINT -Method Get -Headers $HEADERS -Body $queryParameters
        # Checking the response-status; if it is not 200 it will skip the current test
        if ($response.StatusCode -ne 200) {
            Write-Output "Something went wrong;  Status Code: $($response.StatusCode), Status Description: $($response.StatusDescription)"
            return;
        }
        $data = ($response.content | ConvertFrom-Json).data
        $responseData.Add("$($data.ipAddress), $($data.isWhitelisted), $($data.isp), $($data.abuseConfidenceScore),$($data.domain), $($data.isTor), $($data.usageType), $($data.countryCode)") | Out-Null
        Write-Output "Completed Checking $($responseData.Count) IP(s)"
    }
    catch {
        Write-Output "Some error occured"
        $PSItem
    }  
}

# Creating a new out-put.csv file in the current folder with the current response data
Write-Output "$($responseData.Count)  IP(s) checked" 
Write-Output "Creating .\out-put.csv file"
Set-Content -Path ".\out-put.csv" -Value $CSV_FILE_HEADING
Add-Content -Path ".\out-put.csv" -Value $responseData
Write-Output "Completed.!"    