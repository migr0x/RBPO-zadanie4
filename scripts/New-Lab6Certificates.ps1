[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $CourseIssuingStore,

    [string] $StudentId
)

$ErrorActionPreference = 'Stop'

function Read-Password([string] $variable, [string] $prompt) {
    $value = [Environment]::GetEnvironmentVariable($variable, 'Process')
    if (![string]::IsNullOrEmpty($value)) {
        return $value
    }
    $secure = Read-Host -Prompt $prompt -AsSecureString
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
        $secure.Dispose()
    }
}

function Invoke-Keytool([string] $step, [string[]] $arguments) {
    # keytool sends progress messages to stderr even on success.
    $ErrorActionPreference = 'Continue'
    $result = & $keytool '-J-Duser.language=en' '-J-Duser.country=US' @arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "keytool failed during $step (exit $LASTEXITCODE). Check the store path, alias and password."
    }
    return $result
}

function Get-CertificateInfo([string] $path) {
    $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($path)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        [pscustomobject] @{
            Fingerprint = [BitConverter]::ToString($sha256.ComputeHash($certificate.RawData)).Replace('-', ':')
            CommonName = $certificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
            NotBefore = $certificate.NotBefore.ToUniversalTime()
            NotAfter = $certificate.NotAfter.ToUniversalTime()
        }
    }
    finally {
        $sha256.Dispose()
        $certificate.Dispose()
    }
}

if ([string]::IsNullOrWhiteSpace($StudentId)) {
    $StudentId = Read-Host 'Full student card number'
}
if ($StudentId -notmatch '\A[\p{L}\p{Nd}-]{3,40}\z') {
    throw 'Enter the full student card number using letters, digits or hyphens (3-40 characters).'
}

$keytool = (Get-Command keytool -CommandType Application).Source
$project = Split-Path -Parent $PSScriptRoot
$rootCert = Join-Path $project 'tls/course-root-ca.crt'
$courseStore = (Resolve-Path -LiteralPath $CourseIssuingStore).ProviderPath
$local = Join-Path $project 'tls/local'
$outputs = @('course-issuing-ca.crt', 'lab6-issuing-ca.crt', 'lab6-server.crt', 'lab6-server.p12')
foreach ($name in $outputs) {
    if (Test-Path -LiteralPath (Join-Path $local $name)) {
        throw "Back up or move the existing tls/local/$name before issuing a new certificate."
    }
}

$root = Get-CertificateInfo $rootCert
$expectedRoot = '9A:D6:EC:24:B4:E6:18:A8:2C:4B:F7:E1:9C:8A:F3:F4:E0:22:68:03:A3:97:74:5C:98:79:F7:DC:06:11:36:DF'
$expectedCourseIssuer = 'CB:5A:38:65:37:04:ED:D8:FA:96:4E:89:7E:FE:53:C4:9C:BD:1B:5C:C4:E2:88:F3:73:0F:92:FB:FC:76:E6:7F'
if ($root.Fingerprint -cne $expectedRoot) {
    throw 'The course root certificate does not match the expected SHA-256 fingerprint.'
}

$coursePassword = Read-Password 'LAB6_COURSE_CA_PASSWORD' 'Course issuing store password (see assignment)'
$serverPassword = Read-Password 'TLS_KEYSTORE_PASSWORD' 'New server store password (at least 6 characters)'
if ($serverPassword.Length -lt 6) {
    throw 'TLS_KEYSTORE_PASSWORD must contain at least 6 characters for keytool.'
}

$random = [Security.Cryptography.RandomNumberGenerator]::Create()
try {
    $secretBytes = New-Object byte[] 32
    $random.GetBytes($secretBytes)
    $issuingPassword = [Convert]::ToBase64String($secretBytes)
    [Array]::Clear($secretBytes, 0, $secretBytes.Length)
}
finally {
    $random.Dispose()
}

# keytool's :env form keeps passwords out of its command-line arguments.
$passwordVariables = @{
    LAB6_KEYTOOL_COURSE_PASSWORD = $coursePassword
    LAB6_KEYTOOL_ISSUING_PASSWORD = $issuingPassword
    LAB6_KEYTOOL_SERVER_PASSWORD = $serverPassword
}
$previousEnvironment = @{}
foreach ($name in $passwordVariables.Keys) {
    $previousEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}

$stage = Join-Path $local ('.issue-' + [guid]::NewGuid().ToString('N'))
$courseIssuerCert = Join-Path $stage 'course-issuing-ca.crt'
$studentIssuerStore = Join-Path $stage 'lab6-issuing-ca.p12'
$studentIssuerRequest = Join-Path $stage 'lab6-issuing-ca.csr'
$studentIssuerReply = Join-Path $stage 'lab6-issuing-ca-reply.pem'
$studentIssuerCert = Join-Path $stage 'lab6-issuing-ca.crt'
$serverStore = Join-Path $stage 'lab6-server.p12'
$serverRequest = Join-Path $stage 'lab6-server.csr'
$serverReply = Join-Path $stage 'lab6-server-reply.pem'
$serverCert = Join-Path $stage 'lab6-server.crt'

$course = @('-storetype', 'PKCS12', '-keystore', $courseStore, '-storepass:env', 'LAB6_KEYTOOL_COURSE_PASSWORD')
$studentIssuer = @('-storetype', 'PKCS12', '-keystore', $studentIssuerStore, '-storepass:env', 'LAB6_KEYTOOL_ISSUING_PASSWORD')
$server = @('-storetype', 'PKCS12', '-keystore', $serverStore, '-storepass:env', 'LAB6_KEYTOOL_SERVER_PASSWORD')
$issuerExtensions = @('-ext', 'bc:critical=ca:true,pathlen:0', '-ext', 'ku:critical=keyCertSign,cRLSign')
$serverExtensions = @('-ext', 'bc:critical=ca:false', '-ext', 'ku:critical=digitalSignature,keyEncipherment',
    '-ext', 'eku=serverAuth', '-ext', 'san=dns:localhost,ip:127.0.0.1')

try {
    foreach ($name in $passwordVariables.Keys) {
        [Environment]::SetEnvironmentVariable($name, $passwordVariables[$name], 'Process')
    }
    New-Item -ItemType Directory -Path $stage | Out-Null

    $null = Invoke-Keytool 'exporting the course issuer' ($course + @('-exportcert', '-alias', 'courseca', '-rfc', '-file', $courseIssuerCert))
    $courseIssuer = Get-CertificateInfo $courseIssuerCert
    if ($courseIssuer.Fingerprint -cne $expectedCourseIssuer) {
        throw 'The course issuing certificate does not match the expected SHA-256 fingerprint.'
    }
    $now = [DateTime]::UtcNow
    if ($root.NotBefore -gt $now -or $courseIssuer.NotBefore -gt $now) {
        throw 'The course certificates are not valid yet. Check your clock.'
    }
    $remainingDays = [Math]::Floor([Math]::Min(($root.NotAfter - $now).TotalDays, ($courseIssuer.NotAfter - $now).TotalDays))
    # Leave a one-day margin for each issuance so no child outlives its issuer.
    $issuerDays = [int][Math]::Min(30, $remainingDays - 1)
    if ($issuerDays -lt 2) {
        throw 'The course chain is expired or too close to expiration to issue this chain.'
    }
    $serverDays = $issuerDays - 1

    $null = Invoke-Keytool 'generating the student CA key' ($studentIssuer + @('-genkeypair', '-alias', 'lab6-issuing',
        '-keyalg', 'RSA', '-keysize', '2048', '-sigalg', 'SHA256withRSA', '-validity', "$issuerDays", '-dname', "CN=RBPO Lab6 Issuing $StudentId, O=RBPO Lab6") + $issuerExtensions)
    $null = Invoke-Keytool 'creating the student CA request' ($studentIssuer + @('-certreq', '-alias', 'lab6-issuing', '-file', $studentIssuerRequest) + $issuerExtensions)
    $null = Invoke-Keytool 'signing the student CA certificate' ($course + @('-gencert', '-alias', 'courseca',
        '-infile', $studentIssuerRequest, '-outfile', $studentIssuerReply, '-rfc', '-validity', "$issuerDays", '-sigalg', 'SHA256withRSA') + $issuerExtensions)
    $null = Invoke-Keytool 'importing the course root into the student CA store' ($studentIssuer + @('-importcert', '-noprompt', '-alias', 'course-root', '-file', $rootCert))
    $null = Invoke-Keytool 'installing the student CA certificate chain' ($studentIssuer + @('-importcert', '-noprompt', '-alias', 'lab6-issuing', '-file', $studentIssuerReply))
    $null = Invoke-Keytool 'exporting the student CA certificate' ($studentIssuer + @('-exportcert', '-alias', 'lab6-issuing', '-rfc', '-file', $studentIssuerCert))

    $null = Invoke-Keytool 'generating the server key' ($server + @('-genkeypair', '-alias', 'lab6-server',
        '-keyalg', 'RSA', '-keysize', '2048', '-sigalg', 'SHA256withRSA', '-validity', "$serverDays", '-dname', "CN=RBPO Lab6 Server $StudentId, O=RBPO Lab6") + $serverExtensions)
    $null = Invoke-Keytool 'creating the server request' ($server + @('-certreq', '-alias', 'lab6-server', '-file', $serverRequest) + $serverExtensions)
    $null = Invoke-Keytool 'signing the server certificate' ($studentIssuer + @('-gencert', '-alias', 'lab6-issuing',
        '-infile', $serverRequest, '-outfile', $serverReply, '-rfc', '-validity', "$serverDays", '-sigalg', 'SHA256withRSA') + $serverExtensions)
    $null = Invoke-Keytool 'importing the course root into the server store' ($server + @('-importcert', '-noprompt', '-alias', 'course-root', '-file', $rootCert))
    $null = Invoke-Keytool 'installing the server certificate chain' ($server + @('-importcert', '-noprompt', '-alias', 'lab6-server', '-file', $serverReply))
    # The key entry now carries its own chain, so the server needs no separate trust entry.
    $null = Invoke-Keytool 'removing the standalone root entry' ($server + @('-delete', '-alias', 'course-root'))
    $null = Invoke-Keytool 'exporting the server certificate' ($server + @('-exportcert', '-alias', 'lab6-server', '-rfc', '-file', $serverCert))

    $serverListing = (Invoke-Keytool 'checking the server chain' ($server + @('-list', '-v', '-alias', 'lab6-server'))) -join "`n"
    $fingerprints = [regex]::Matches($serverListing, '(?m)^\s*SHA256:\s*([A-F0-9:]+)\s*$')
    $leaf = Get-CertificateInfo $serverCert
    $issuer = Get-CertificateInfo $studentIssuerCert
    if ($leaf.CommonName -cne "RBPO Lab6 Server $StudentId" -or $issuer.CommonName -cne "RBPO Lab6 Issuing $StudentId") {
        throw 'The student card number was not encoded correctly in both certificate subjects.'
    }
    $expectedChain = @($leaf.Fingerprint, $issuer.Fingerprint, $expectedCourseIssuer, $expectedRoot)
    if ($serverListing -notmatch '(?m)^Entry type: PrivateKeyEntry\s*$' -or $fingerprints.Count -ne $expectedChain.Count) {
        throw 'The server key entry does not contain the required four certificates.'
    }
    for ($index = 0; $index -lt $expectedChain.Count; $index++) {
        if ($fingerprints[$index].Groups[1].Value -cne $expectedChain[$index]) {
            throw 'The installed server chain does not match the issued certificates.'
        }
    }

    foreach ($name in $outputs) {
        Move-Item -LiteralPath (Join-Path $stage $name) -Destination (Join-Path $local $name)
    }
    Write-Host 'Created tls/local/lab6-server.p12 with four certificates and exported public certificates under tls/local.'
}
finally {
    foreach ($name in $passwordVariables.Keys) {
        [Environment]::SetEnvironmentVariable($name, $previousEnvironment[$name], 'Process')
    }
    if (Test-Path -LiteralPath $stage -PathType Container) {
        $resolvedStage = (Resolve-Path -LiteralPath $stage).ProviderPath
        $resolvedLocal = (Resolve-Path -LiteralPath $local).ProviderPath
        if ([IO.Path]::GetDirectoryName($resolvedStage) -eq $resolvedLocal -and
            [IO.Path]::GetFileName($resolvedStage) -match '^\.issue-[a-f0-9]{32}$') {
            Remove-Item -LiteralPath $resolvedStage -Recurse -Force
        }
    }
}
