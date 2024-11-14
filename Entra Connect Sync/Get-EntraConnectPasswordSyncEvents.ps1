function Get-EntraConnectPasswordSyncEvents.ps1 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [String]$UserPrincipalName,
        [Switch]$Last24Hours,
        [Switch]$LastHour,
        [Switch]$Last10Minutes,
        [Switch]$SuccessOnly,
        [Switch]$FailedOnly,
        [Switch]$ChangeFromEntraID,
        [Switch]$ChangeFromAD
    )
    
    <# 
to see in GUI, go to Connectors > AD connector > Search Connector Space > Search objet or search All > choose object > Log. You'll see Log about pass sync
eventID list: https://docs.microsoft.com/en-us/troubleshoot/azure/active-directory/troubleshoot-pwd-sync#informational-no-action-required

Event ID 656
Password synchronization indicates that a password change was detected and tries to sync it to Azure AD.
It identifies the user or users whose password changed and will be synced. Each batch contains at least one user and at most 50 users.

Event ID 657
Users whose password successfully synced. (Result: Success)
Users whose password didn't sync. (Result: Failed)

Examples Get-Winevent 657
Password Change Result - Anchor : base64==, Dn : CN=user,OU=OUName,DC=domain,DC=com, PwdChangeOnLogon=False, Result : Success.

<forest-info>
  <partition-name>DOMAIN.COM</partition-name>
  <connector-id>Connector GUID</connector-id>
</forest-info>

#>

    [System.Collections.Generic.List[PSObject]]$changePasswordArray = @()
    [System.Collections.Generic.List[PSObject]]$eventsArray = @()
    <#
# https://learn.microsoft.com/en-us/entra/identity/authentication/troubleshoot-sspr-writeback
656 # passworcChangeTry - password change was detected and tries to sync it to Azure AD.
657 # passworcChangeResult - users whose password successfully synced. (Result: Success)
31006 # resetPasswordStart - Password reset request received
31007 # resetPasswordSuccess - Password reset request completed successfully
31008 # resetPasswordFailed - Password reset request failed
31009 # ResetUserPasswordByAdminStart
31010 # ResetUserPasswordByAdminSuccess
31011 # ResetUserPasswordByAdminFailed
611 # passwordHash failed
33002 # This event indicates that the user who is trying to reset or change a password was not found in the on-premises directory. This error can occur when the user has been deleted on-premises but not in the cloud. This error can also occur if there's a problem with sync. Check your sync logs and the last few sync run details for more information. Occur also when user is not in the scope of selective password sync
#>

    # event log for PasswordReset : https://learn.microsoft.com/en-us/azure/active-directory/authentication/troubleshoot-sspr-writeback


    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        Write-Warning 'ActiveDirectory module not found. Please install RSAT tools'
        return
    }
    
    if ($SuccessOnly) {
        $filterHashTable = @{'LogName' = 'Application'; 'Id' = 657, 31007, 31010 }
    }
    elseif ($FailedOnly) {
        $filterHashTable = @{'LogName' = 'Application'; 'Id' = 31008, 33008, 611, 33002, 31011 }
    }
    else {
        $filterHashTable = @{'LogName' = 'Application'; 'Id' = 656, 657, 31006, 31007, 31008, 33008, 611, 33002, 31009, 31010, 31011 }
    }
    
    if ($Last24Hours) {
        $filterHashTable.Add('StartTime', (Get-Date).AddHours(-24))
    }
    elseif ($LastHour) {
        $filterHashTable.Add('StartTime', (Get-Date).AddHours(-1))
    }
    elseif ($Last10Minutes) {
        $filterHashTable.Add('StartTime', (Get-Date).AddMinutes(-10))
    }

    Get-WinEvent -FilterHashtable $filterHashTable -ErrorAction SilentlyContinue | ForEach-Object { $eventsArray.Add($_) }

    foreach ($event in $eventsArray) {
        switch ($event.ID) {
            656 {
                $eventMessages = $event.Message -split "`n" | Where-Object { $_ -like 'Password Change Request*' } 
                                                     
                foreach ($eventMessage in $eventMessages) {
                    $eventMessageSplit = $eventMessage -split ', '  
                           
                    $object = [PSCustomObject][ordered]@{
                        Date             = $event.TimeCreated
                        User             = ($eventMessageSplit | Where-Object { $_ -like 'Dn :*' }).replace('Dn : ', '')
                        Details          = '-'
                        PwdChangeOnLogon = '-'
                        Status           = 'Password Change Request'
                        Flow             = 'AD to Entra ID'
                        EventID          = $event.ID
                    }

                    $changePasswordArray.Add($object)
                }

                break
            }

            657 {
                $eventMessages = $event.Message -split "`n" | Where-Object { $_ -like 'Password Change Result*' } 
                                                     
                foreach ($eventMessage in $eventMessages) {
                    $eventMessageSplit = $eventMessage -split ', '  
                           
                    $object = [PSCustomObject][ordered]@{
                        Date             = $event.TimeCreated
                        User             = ($eventMessageSplit | Where-Object { $_ -like 'Dn :*' }).replace('Dn : ', '')
                        Details          = '-'
                        PwdChangeOnLogon = ($eventMessageSplit | Where-Object { $_ -like 'PwdChangeOnLogon=*' }).replace('PwdChangeOnLogon=', '')
                        Status           = 'Password Change ' + ($eventMessageSplit | Where-Object { $_ -like 'Result :*' }).replace('Result : ', '')
                        Flow             = 'AD to Entra ID'
                        EventID          = $event.ID
                    }

                    $changePasswordArray.Add($object)
                }

                break
            }

            31006 {
                $object = [PSCustomObject][ordered]@{
                    Date             = $event.TimeCreated
                    User             = ($event.Message -split 'Details: ')[1]
                    Details          = '-'
                    PwdChangeOnLogon = '-'
                    Status           = 'ResetPassword - ChangePasswordRequestStart'
                    Flow             = 'Entra ID to AD'
                    EventID          = $event.ID
                }

                $changePasswordArray.Add($object)

                break
            }

            31007 {
                $object = [PSCustomObject][ordered]@{
                    Date             = $event.TimeCreated
                    User             = ($event.Message -split 'UserPrincipalName: ')[1]
                    Details          = '-'
                    PwdChangeOnLogon = '-'
                    Status           = 'ResetPassword - ChangePasswordSuccess'
                    Flow             = 'Entra ID to AD'
                    EventID          = $event.ID
                }

                $changePasswordArray.Add($object)

                break
            }
        
            31008 {
                $object = [PSCustomObject][ordered]@{
                    Date             = $event.TimeCreated
                    User             = ($event.Message -split 'UserPrincipalName: ')[1]
                    Details          = '-'
                    PwdChangeOnLogon = '-'
                    Status           = 'ResetPassword - ChangePasswordFailed'
                    Flow             = 'Entra ID to AD'
                    EventID          = $event.ID
                }

                $changePasswordArray.Add($object)

                break
            }

            33008 {
                $object = [PSCustomObject][ordered]@{
                    Date             = $event.TimeCreated
                    # message is xx@domain.com, Details: Microsoft.CredentialManagement.OnPremisesPasswordReset.Shared.PasswordResetException: Synchronization Engine returned an error hr=80230619, message=A restriction prevents the password from being changed to the current one specified.
                    User             = (($event.Message -split 'UserPrincipalName: ')[1] -split ', Details')[0]
                    PwdChangeOnLogon = '-'
                    Details          = (($event.Message -split 'message=')[1] -split ', Context:')[0]
                    Status           = 'ResetPassword - ChangePasswordFailed'
                    Flow             = 'Entra ID to AD'
                    EventID          = $event.ID
                }

                $changePasswordArray.Add($object)

                break
            }

            611 {
                $object = [PSCustomObject][ordered]@{
                    Date             = $event.TimeCreated
                    User             = '-'
                    Details          = $event.Message.split("`n")[0] # get first line
                    PwdChangeOnLogon = '-'
                    Status           = 'Password Hash Failed'
                    Flow             = 'AD to Entra ID'
                    EventID          = $event.ID
                }

                $changePasswordArray.Add($object)

                break
            }

            33002 {
                $object = [PSCustomObject][ordered]@{
                    Date             = $event.TimeCreated
                    User             = [regex]::Match($event.Message, '(?<=UserPrincipalName:\s)[^,\s]+')
                    Details          = [regex]::Match($event.Message, '(?<=message=)[^,]+')
                    PwdChangeOnLogon = '-'
                    Status           = 'ResetPassword - ChangePasswordFailed'
                    Flow             = 'Entra ID to AD'
                    EventID          = $event.ID
                }

                $changePasswordArray.Add($object)

                break
            }

            31009 {
                # TrackingId: <id>, ResetUserPasswordByAdminStart, Details: <upn>

                $object = [PSCustomObject][ordered]@{
                    Date             = $event.TimeCreated
                    User             = ($event.Message -split 'Details: ')[1]
                    Details          = '-'
                    PwdChangeOnLogon = '-'
                    Status           = 'ResetPasswordByAdminStart'
                    Flow             = 'Entra ID to AD'
                    EventID          = $event.ID
                }

                $changePasswordArray.Add($object)

                break
            }

            31010 {
                # TrackingId: <id>, ResetUserPasswordByAdminSuccess, Details: Context: cloudAnchor: <User_ID>, SourceAnchorValue: xxx, AdminUpn: <upn>, UserPrincipalName <upn>, ForcePasswordChange: <value>
                $object = [PSCustomObject][ordered]@{
                    Date             = $event.TimeCreated
                    #User             = ($eventMessage -split 'DN : ' -split ', Change Date :')[1]
                    User             = [regex]::Match($event.Message, '(?<=UserPrincipalName:\s)[^,\s]+')
                    #Details          = ($eventMessageSplit | Where-Object { $_ -like 'AdminUpn:*' }).replace('AdminUpn:', '')
                    Details          = "AdminUPN : $([regex]::Match($event.Message, '(?<=AdminUpn:\s)[^,\s]+'))"
                    #PwdChangeOnLogon = ($eventMessageSplit | Where-Object { $_ -like 'ForcePasswordChange:*' }).replace('ForcePasswordChange:', '')
                    PwdChangeOnLogon = [regex]::Match($event.Message, '(?<=ForcePasswordChange:\s)[^,\s]+')
                    Status           = 'ResetUserPasswordByAdminSuccess (or Change Password via https://mysignins.microsoft.com/security-info)'
                    Flow             = 'Entra ID to AD'
                    EventID          = $event.ID
                }

                $changePasswordArray.Add($object)

                break
            }

            31011 {
                $object = [PSCustomObject][ordered]@{
                    Date             = $event.TimeCreated
                    User             = ($event.Message -split 'UserPrincipalName: ')[1]
                    Details          = '-'
                    PwdChangeOnLogon = '-'
                    Status           = 'ResetUserPasswordByAdminFailed (or Change Password via https://mysignins.microsoft.com/security-info)'
                    Flow             = 'Entra ID to AD'
                    EventID          = $event.ID
                }

                $changePasswordArray.Add($object)

                break
            }

            Default {
                break
            }
        }
    }

    if ($UserPrincipalName) {
        $user = Get-ADUser -Filter "userprincipalname -eq '$UserPrincipalName'"
        $changePasswordArray = $changePasswordArray | Where-Object { $_.User -eq $user.UserPrincipalName -or $_.User -eq $user.DistinguishedName }
    }

    if ($ChangeFromEntraID) {
        $changePasswordArray = $changePasswordArray | Where-Object { $_.Flow -eq 'Entra ID to AD' }
    }
    elseif ($ChangeFromAD) {
        $changePasswordArray = $changePasswordArray | Where-Object { $_.Flow -eq 'AD to Entra ID' }
    }
    return $changePasswordArray | Sort-Object Date -Descending
}