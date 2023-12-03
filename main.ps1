. .\key.ps1
"
####################################################################################################
This script is created by SivaMani to automate the IP reputation checking using the AbuseIPDB API.

To use this script -- Get your API key from AbuseIPDB.

Replace the {`$KEY} value with your API-Key
####################################################################################################
"

# {$IPS} - is an array; which holds a list of IPs we need to check
$IPS = ("157.230.80.76");

$EndPoint = "https://api.abuseipdb.com/api/v2/check"

# Headers for the endpoint
# Add your API-Key - Get the key from Abuseipdb
# {$KEY} -- holds the API-Key value -- Key need to passed along with the request
$Headers = @{
    "key"    = $KEY
    "Accept" = "application/json"
}


# Header for the CSV file
$CSV_Heading = "IPAddress, Whitelisted,ISP, AbuseConfidenceScore, Domain, IsTor, UsageType,  CountryCode"
$Response_Data = New-Object System.Collections.ArrayList
$index = 0

Write-Output "Checking IPs reputation"

foreach ($ipaddress in $IPS) {

    # URL parameters
    $Params = @{
        "ipAddress" = $ipaddress
    }

    try {

        $Response = Invoke-WebRequest -Uri $EndPoint -Method Get -Headers $Headers -Body $Params

        # Checking the response-status; if it is not 200 it will skip the current test
        if ($Response.StatusCode -ne 200) {
            Write-Output "Something went wrong;  Status Code: $($Response.StatusCode), Status Description: $($Response.StatusDescription)"
            return;
        }

        $Data = ($Response.content | ConvertFrom-Json).data
        $index = $Response_Data.Add("$($Data.ipAddress), $($Data.isWhitelisted), $($Data.isp), $($Data.abuseConfidenceScore),$($Data.domain), $($Data.isTor), $($Data.usageType), $($Data.countryCode)");
        Write-Output "Completed Checking $($index + 1) IP(s)"
    }
    catch {
        Write-Output "Some error occured"
        $_.Exception.Response
    }
    
}

# Creating a new out-put.csv file in the current folder with the current response data
Write-Output "$($index + 1)  IP(s) checked" 
Write-Output "Creating .\out-put.csv file"
Set-Content -Path ".\out-put.csv" -Value $CSV_Heading
Add-Content -Path ".\out-put.csv" -Value $Response_Data
Write-Output "Completed.!"    