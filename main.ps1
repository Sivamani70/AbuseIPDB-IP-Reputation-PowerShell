. .\key.ps1
"
####################################################################################################
This script is created by SivaMani to automate the IP reputation checking using the AbuseIPDB API.

To use this script -- Get your API key from AbuseIPDB.

Replace the {`$KEY} value with your API-Key
####################################################################################################
"

# {$IPS} - is an array; which holds a list of IPs we need to check
$IPS = ("157.230.80.76", "208.100.26.241", "87.236.176.15", "91.92.241.122", "157.245.216.203", "43.156.36.172", "159.223.121.107", "221.151.220.160", "47.90.253.99", "47.90.206.147", "104.156.155.31", "77.90.185.183", "45.143.200.46", "205.185.119.211", "81.0.99.4", "185.94.111.1", "92.63.197.89", "45.129.14.236", "77.222.111.198", "191.241.163.14", "94.102.61.54", "5.200.70.148", "77.90.185.189", "118.123.105.92", "192.241.211.23", "162.216.150.228", "162.142.125.91", "94.102.61.41", "162.142.125.237", "98.98.147.18", "162.216.150.30", "118.25.6.39", "223.198.202.171", "220.180.170.188", "219.137.177.169", "219.135.213.202", "217.182.196.20", "217.182.175.39", "217.182.72.193", "217.174.206.98", "217.170.198.17", "217.160.75.121", "217.160.67.32", "217.130.101.13", "217.116.205.56", "217.112.89.55", "217.28.185.214", "217.25.40.254", "216.152.252.254", "83.221.222.241", "82.156.151.88", "82.156.143.127", "82.151.125.214", "82.138.28.34", "82.112.22.150", "80.227.147.94", "80.187.114.206", "80.187.114.19", "80.187.114.3", "80.187.98.252", "79.174.234.38", "79.136.18.138", "79.110.62.88", "78.142.18.151", "78.111.249.76", "77.92.250.134", "77.91.124.182", "77.90.185.130", "77.74.78.44", "77.40.62.152", "77.40.61.145", "77.39.8.30", "77.7.104.1", "74.201.28.5", "74.192.234.21", "70.35.199.129", "68.132.165.85", "64.145.93.229", "62.234.39.248", "62.163.92.71", "62.19.207.131", "61.191.103.104", "61.188.233.163", "61.184.85.39", "61.174.28.202", "61.160.119.116", "61.134.36.102", "61.95.130.118", "61.84.226.236", "60.222.244.32", "60.173.252.24", "60.13.138.107", "60.13.8.218", "59.182.2.167", "59.153.103.28", "59.88.203.95", "59.63.148.106", "59.49.131.51", "59.31.148.130", "58.241.13.219", "58.216.184.66", "58.216.170.50", "58.212.122.130", "58.209.76.202", "58.208.99.6", "58.208.84.245", "58.145.188.231", "58.42.233.242", "58.11.96.97", "58.11.80.76", "58.11.55.82", "58.8.10.144", "52.162.176.90", "51.222.171.127", "51.52.243.18", "51.52.76.159", "50.227.179.195", "50.87.144.20", "49.228.234.212", "49.85.207.207", "49.82.27.150", "49.81.122.25", "49.72.14.84", "49.49.251.145", "47.253.42.147", "46.251.225.66", "46.241.58.40", "46.229.134.80", "46.140.242.46", "46.21.91.191", "46.3.197.107", "45.221.11.39", "45.181.30.254", "45.172.82.70", "45.138.16.191", "45.137.22.151", "45.133.235.202", "45.133.232.222", "45.131.192.213", "45.131.192.127", "45.123.222.164", "45.122.240.178", "45.116.114.34", "45.88.40.184", "45.83.64.137", "45.81.39.43", "45.80.158.241", "45.66.230.234", "45.66.230.39");

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