. .\menu.ps1

function GetAwsAccessToken() {
    $awsTokenFilePath = "C:\Users\${env:UserName}\.aws\sso\cache"
    $accessToken = ""
    $files = Get-ChildItem $awsTokenFilePath

    foreach ($file in $files) {
        $content = Get-Content $file.FullName
        if ($content.Contains("startUrl")) {
            $fileTokenText = [string]::Join("`n", $content)
            $match = [regex]::Match($fileTokenText, '"accessToken":\s*"([^"]*)".*?"expiresAt":\s*"([^"]*)"')
            if ($match.Success) {
                $accessToken = $match.Groups[1].Value
                $expirationString = $match.Groups[2].Value
                break
            }
        }
    }

    if (!([string]::IsNullOrEmpty($expirationString)) -and ([DateTime]$expirationString) -lt [DateTime]::UtcNow) {
        Write-Host "accessToken expired"
        $accessToken = ""
    } else {
        Write-Host "Found valid accessToken"
    }
    return $accessToken
}


$awsConfigFilePath = "C:\Users\${env:UserName}\.aws\config"
$fileContent = Get-Content $awsConfigFilePath
$text = [string]::Join("`n", $fileContent)
$profileMatches = [regex]::Matches($text, '(\[profile (.*))]((.|\n)*?)(sso_region = (.*))((.|\n)*?)(sso_account_id = (.*))((.|\n)*?)(sso_role_name = (.*))')
$profiles=@{}
$regions=@{}
$accounts=@{}
$roles=@{}
Foreach($profileMatch in $profileMatches) {
	$profile = $profileMatch.Groups[2].Value
	$profiles.Add($profile, $profile)
	$region = $profileMatch.Groups[6].Value
	$regions.Add($profile, $region)
	$account = $profileMatch.Groups[10].Value
	$accounts.Add($profile, $account)
	$role = $profileMatch.Groups[14].Value
	$roles.Add($profile, $role)
	}
$selectedProfile = fShowMenu "Choose profile" $profiles
$selectedAccount = $accounts[$selectedProfile]
$selectedRole = $roles[$selectedProfile]
$selectedRegion = $regions[$selectedProfile]
Write-Host "Profile: ${selectedProfile}, Account: ${selectedAccount}, Role: ${selectedRole}, Region: ${selectedRegion}"

$accessToken = GetAwsAccessToken
if([string]::IsNullOrEmpty($accessToken))
{
	Write-Host "Trying to login"
	aws sso login --profile $selectedProfile
	$accessToken = GetAwsAccessToken
}
if([string]::IsNullOrEmpty($accessToken))
{
	Write-Host "Error getting accessToken"
	Exit
}

$credentials = aws sso get-role-credentials --account-id $selectedAccount --role-name $selectedRole --access-token $accessToken --region $selectedRegion

$jsonCredentials = ($credentials | ConvertFrom-Json).rolecredentials[0]

if(![string]::IsNullOrEmpty($jsonCredentials))
{
$aws_access_key_id = $jsonCredentials.accessKeyId
$aws_secret_access_key = $jsonCredentials.secretAccessKey
$aws_session_token = $jsonCredentials.sessionToken

$fileContent = "[default]
aws_access_key_id=${aws_access_key_id}
aws_secret_access_key=${aws_secret_access_key}
aws_session_token=${aws_session_token}"

$awsConfigFilePath = "C:\Users\${env:UserName}\.aws\credentials"
Set-Content $awsConfigFilePath $fileContent
Write-Host "Credentials correctly stored in ${awsConfigFilePath}"
}
else
{
	Write-Host "Something went wrong"
}
