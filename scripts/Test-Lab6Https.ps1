[CmdletBinding()]
param(
    [uri] $BaseUrl = 'https://localhost:8443',
    [ValidateNotNullOrEmpty()]
    [string] $Username = 'chief_editor',
    [securestring] $Password
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)

if (!$BaseUrl.IsAbsoluteUri -or $BaseUrl.Scheme -ne 'https' -or
    $BaseUrl.DnsSafeHost -notin @('localhost', '127.0.0.1') -or
    $BaseUrl.AbsolutePath -ne '/' -or $BaseUrl.Query -or $BaseUrl.Fragment -or $BaseUrl.UserInfo) {
    throw 'BaseUrl must be a local HTTPS origin, for example https://localhost:8443.'
}

$curl = (Get-Command curl.exe -CommandType Application).Source
$rootCertificate = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../tls/course-root-ca.crt')).Path
$curlOptions = @('--disable', '--silent', '--show-error', '--max-time', '15',
    '--cacert', $rootCertificate, '--tlsv1.3', '--tls-max', '1.3',
    '--proto', '=https', '--noproxy', '*', '--write-out', '\n%{http_code}')
if ((& $curl --disable --version | Select-Object -First 1) -match 'Schannel') {
    # The course certificates need no network lookup for their unavailable revocation data.
    $curlOptions += '--ssl-revoke-best-effort'
}

function ConvertTo-CurlConfigValue {
    param([string] $Value)
    '"' + $Value.Replace('\', '\\').Replace('"', '\"').Replace("`r", '\r').Replace("`n", '\n') + '"'
}

function Invoke-LabRequest {
    param(
        [string] $Route,
        [int] $ExpectedStatus,
        [hashtable] $Payload,
        [string] $AccessToken
    )

    # Pass credentials and tokens over stdin, so none appear in curl process arguments.
    $requestConfig = @('url = ' + (ConvertTo-CurlConfigValue ([uri]::new($BaseUrl, $Route).AbsoluteUri)))
    if ($null -ne $Payload) {
        $requestConfig += 'header = "Content-Type: application/json"'
        $requestConfig += 'data-binary = ' + (ConvertTo-CurlConfigValue ($Payload | ConvertTo-Json -Compress))
    }
    if ($AccessToken) {
        $requestConfig += 'header = ' + (ConvertTo-CurlConfigValue "Authorization: Bearer $AccessToken")
    }
    $response = @($requestConfig | & $curl @curlOptions --config -)
    if ($LASTEXITCODE -ne 0) {
        throw "curl failed for $Route (exit $LASTEXITCODE)."
    }
    if ($response.Count -lt 2 -or $response[-1] -ne [string] $ExpectedStatus) {
        throw "Unexpected HTTP status for $Route. Expected $ExpectedStatus."
    }
    try {
        $response[0..($response.Count - 2)] -join "`n" | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw "Expected a JSON response from $Route."
    }
}

function Assert-TokenPair {
    param($Pair)
    if (!($Pair.accessToken -is [string] -and $Pair.accessToken -match '^[-\w]+\.[-\w]+\.[-\w]+$') -or
        !($Pair.refreshToken -is [string] -and $Pair.refreshToken -match '^[-\w]+\.[-\w]+\.[-\w]+$')) {
        throw 'Expected accessToken and refreshToken in compact JWT form.'
    }
}

if ($null -eq $Password -and $Username -eq 'chief_editor') {
    $loginPassword = 'EditorDemo!2026' # Public demo fixture from the project README.
} else {
    if ($null -eq $Password) { $Password = Read-Host 'Password' -AsSecureString }
    $loginPassword = [System.Net.NetworkCredential]::new('', $Password).Password
}

$deviceId = 'lab6-https-' + [guid]::NewGuid().ToString('N')
$first = Invoke-LabRequest -Route '/auth/login' -ExpectedStatus 200 -Payload @{
    username = $Username
    password = $loginPassword
    deviceId = $deviceId
}
Assert-TokenPair $first
Write-Host 'PASS: TLS 1.3, certificate chain and hostname verified. Login returned a JWT pair.'

$current = Invoke-LabRequest -Route '/api/auth/me' -ExpectedStatus 200 -AccessToken $first.accessToken
if ($current.username -ne $Username) { throw 'Wrong authenticated username.' }
Write-Host 'PASS: access token opened the protected endpoint.'

$payload = @{ refreshToken = $first.refreshToken }
$next = Invoke-LabRequest -Route '/auth/refresh' -ExpectedStatus 200 -Payload $payload
Assert-TokenPair $next
if ($next.accessToken -ceq $first.accessToken -or $next.refreshToken -ceq $first.refreshToken) {
    throw 'Refresh did not rotate both tokens.'
}
Write-Host 'PASS: refresh returned a new pair.'

$replay = Invoke-LabRequest -Route '/auth/refresh' -ExpectedStatus 401 -Payload $payload
if ($replay.PSObject.Properties['accessToken'] -or $replay.PSObject.Properties['refreshToken']) {
    throw 'A rejected refresh returned a token.'
}
$current = Invoke-LabRequest -Route '/api/auth/me' -ExpectedStatus 200 -AccessToken $next.accessToken
if ($current.username -ne $Username) { throw 'Wrong authenticated username after refresh.' }
Write-Host 'PASS: old refresh returned 401; the new access token still works.'
Write-Host "Device ID for SQL verification: $deviceId"
