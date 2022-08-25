# SetAwsCredentials
Script to quickly set your AWS credentials

## Requirements:
* Windows
* Powershell
* AWS CLI

## Settings:
* Add your profiiles to *C:\Users\\[YourUserName]\\.aws\config* in the following format:
```
[profile profile1]
sso_start_url = https://........./start#/
sso_region = login region (e.g. us-east-1)
sso_account_id = xxxxxxxxx
sso_role_name = xxxxxxxxx
region = region (e.g. eu-west-1)
output = json

[profile profile2]
sso_start_url = https://........./start#/
sso_region = login region (e.g. us-east-1)
sso_account_id = xxxxxxxxx
sso_role_name = xxxxxxxxx
region = region (e.g. eu-west-1)
output = json
```

## Usage:
run ```.\SetAwsCredentials.ps1``` and select the profile from the menu.
</br>The script will save your credentials in C:\Users\\[YourUserName]\\.aws\credentials
