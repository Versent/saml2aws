Import-Module ADFS
Add-ADFSRelyingPartyTrust -Name "Amazon Web Services" -MetadataURL "https://signin.aws.amazon.com/static/saml-metadata.xml" -MonitoringEnabled:$true -AutoUpdateEnabled:$true

$ruleSet = New-AdfsClaimRuleSet -ClaimRuleFile ((pwd).Path + "\claims.txt")
$authSet = New-AdfsClaimRuleSet -ClaimRuleFile ((pwd).Path + "\auth.txt")
Set-AdfsRelyingPartyTrust -TargetName "Amazon Web Services" -IssuanceTransformRules $ruleSet.ClaimRulesString -IssuanceAuthorizationRules $authSet.ClaimRulesString 
