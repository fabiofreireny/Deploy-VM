# From https://virtuallysober.com/2018/01/04/introduction-to-powershell-rest-api-authentication/

# Define vCenter server
$RESTAPIServer = "nycvcsa01.strozllc.public"

# Define login credentials
$RESTAPIUser = "strozllc.public\svc_gambrinus"
$RESTAPIPassword = "tvKJ1P1jVdEtUBh6xqYm"

# Run once to create secure credential file
#GET-CREDENTIAL –Credential (Get-Credential) | EXPORT-CLIXML "C:\SecureString\SecureCredentials.xml"
# Run at the start of each script to import the credentials
#$Credentials = IMPORT-CLIXML "C:\SecureString\SecureCredentials.xml"
#$RESTAPIUser = $Credentials.UserName
#$RESTAPIPassword = $Credentials.GetNetworkCredential().Password

# Add this to ignore untrusted certificates and use TLS1.2 if possible
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'

# Authentication URL
$BaseAuthURL = "https://" + $RESTAPIServer + "/rest/com/vmware/cis/"
$BaseURL = "https://" + $RESTAPIServer + "/rest/vcenter/"
$vCenterSessionURL = $BaseAuthURL + "session"
$Header = @{"Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($RESTAPIUser+":"+$RESTAPIPassword))}
$Type = "application/json"

# Authenticate
Try {
    $vCenterSessionResponse = Invoke-RestMethod -Uri $vCenterSessionURL -Headers $Header -Method POST -ContentType $Type
}
Catch {
    $_.Exception.ToString()
    $error[0] | Format-List -Force
}
# Extracting the session ID from the response
$vCenterSessionHeader = @{'vmware-api-session-id' = $vCenterSessionResponse.value}

# Get VM List
$ClusterListURL = $BaseURL+"cluster"
Try {
    $ClusterListJSON = Invoke-RestMethod -Method Get -Uri $ClusterListURL -TimeoutSec 100 -Headers $vCenterSessionHeader -ContentType $Type
    $ClusterList = $ClusterListJSON.value
}
Catch {
    $_.Exception.ToString()
    $error[0] | Format-List -Force
}

$ClusterList | Format-Table -AutoSize