<#
    .SYNOPSIS
        Deploy Virtual Machines in Microsoft Azure

    .DESCRIPTION
        This Script deploys Virtual Machines in Microsoft Azure

    .NOTES

        Version:        2.0

        Author:         Robert Tholen
                        info@m365Island.com

        Creation Date:  10.07.2019

        Plattform:      Windows 10, Windows Server 2019


        Changelog:      27.01.2021      2.0 - Add argumentcompleter to all Parameters
                        10.07.2019      1.0 - Initial script development

    .COMPONENT
        Azure PowerShell Modules
        Az.compute

    .LINK

    .Parameter AzSubscription
        Description for a parameter in param definition section.
        Each parameter requires a separate description.
        The name in the description and the parameter section must match.

    .Parameter AzLocation
        Description for a parameter in param definition section.
        Each parameter requires a separate description.
        The name in the description and the parameter section must match.

    .Parameter AzVMSize
        Description for a parameter in param definition section.
        Each parameter requires a separate description.
        The name in the description and the parameter section must match.

    .Parameter AzResourceGroup
        Description for a parameter in param definition section.
        Each parameter requires a separate description.
        The name in the description and the parameter section must match.

    .Parameter virtualMachineName
        Description for a parameter in param definition section.
        Each parameter requires a separate description.
        The name in the description and the parameter section must match.

    .Parameter VMTimeZone
        Description for a parameter in param definition section.
        Each parameter requires a separate description.
        The name in the description and the parameter section must match.

    .Parameter AzImagePublisher
        Description for a parameter in param definition section.
        Each parameter requires a separate description.
        The name in the description and the parameter section must match.

    .Parameter AzImageOffer
        Description for a parameter in param definition section.
        Each parameter requires a separate description.
        The name in the description and the parameter section must match.

    .Parameter AzImageSkus
        Description for a parameter in param definition section.
        Each parameter requires a separate description.
        The name in the description and the parameter section must match.

    .Parameter AzvirtualNetwork
        Description for a parameter in param definition section.
        Each parameter requires a separate description.
        The name in the description and the parameter section must match.

    .Parameter AzVirtualNetworkSubnet
        Description for a parameter in param definition section.
        Each parameter requires a separate description.
        The name in the description and the parameter section must match.

    .Parameter LocalAdmin
        Description for a parameter in param definition section.
        Each parameter requires a separate description.
        The name in the description and the parameter section must match.

    .Parameter LocalAdminPassword
        Description for a parameter in param definition section.
        Each parameter requires a separate description.
        The name in the description and the parameter section must match.

    .Parameter JoinDomainName
        Description for a parameter in param definition section.
        Each parameter requires a separate description.
        The name in the description and the parameter section must match.

    .Parameter JoinDomainUser
        Description for a parameter in param definition section.
        Each parameter requires a separate description.
        The name in the description and the parameter section must match.

    .Parameter JoinDomainUserPW
        Description for a parameter in param definition section.
        Each parameter requires a separate description.
        The name in the description and the parameter section must match.

    .Example
        Mit Domain Join

        New-AzVMfromMicrosoft -AzSubscription 'My Subscription' -AzLocation germanywestcentral -AzVMSize Standard_D2_v2 -AzResourceGroup 'My Resourcegroup' -virtualMachineName 'My VM Name' -VMTimeZone 'W. Europe Standard Time' -AzImagePublisher MicrosoftWindowsServer -AzImageOffer WindowsServer -AzImageSkus 2019-Datacenter -AzvirtualNetwork 'My Virtual Network' -AzVirtualNetworkSubnet 'My Virutal Network Subnet' -LocalAdmin 'Local Admin Account' -LocalAdminPassword 'Password' -JoinDomainName 'Active Directory Domain FQDN' -JoinDomainUser 'Domain\Bneutzer' -JoinDomainUserPW 'Password'

    .Example
        Ohne Domain Join

        New-AzVMfromMicrosoft -AzSubscription 'My Subscription' -AzLocation germanywestcentral -AzVMSize Standard_D2_v2 -AzResourceGroup 'My Resourcegroup' -virtualMachineName 'My VM Name' -VMTimeZone 'W. Europe Standard Time' -AzImagePublisher MicrosoftWindowsServer -AzImageOffer WindowsServer -AzImageSkus 2019-Datacenter -AzvirtualNetwork 'My Virtual Network' -AzVirtualNetworkSubnet 'My Virutal Network Subnet' -LocalAdmin 'Local Admin Account' -LocalAdminPassword 'Password'

    .Example

        New-AzVMfromMicrosoft -AzSubscription 'My Subscription' -AzLocation germanywestcentral -AzVMSize Standard_D2_v2 -AzResourceGroup 'My Resourcegroup' -virtualMachineName 'My VM Name' -VMTimeZone 'W. Europe Standard Time' -AzImageSkus 2019-Datacenter -AzvirtualNetwork 'My Virtual Network' -AzVirtualNetworkSubnet 'My Virutal Network Subnet' -LocalAdmin 'Local Admin Account' -LocalAdminPassword 'Password'
#>

param(

    ##
    ## Subscription ID
    ##
    [argumentcompleter({
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

            $SubscriptionIDs = (Get-AzSubscription).Name
            $SubscriptionIDs | where-object {$_ -like "$wordToComplete*"} | foreach-Object { if ($_.contains(' ')) { "'" + $_ + "'" }else { $_ } }

        }
    )]
    [Parameter(Mandatory = $true)]
    [string]$AzSubscription,

    ##
    ## Azure Location
    ##
    [argumentcompleter({
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

            $locations = (Get-AzLocation).Location
            $locations | where-object {$_ -like "$wordToComplete*"} | foreach-Object { if ($_.contains(' ')) { "'" + $_ + "'" }else { $_ } }
        }
    )]
    [Parameter(Position = 0, Mandatory = $true)]
    [String]$AzLocation,

    ##
    ## virtual machine size
    ##
    [argumentcompleter({
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

            $AzVMSizes = (Get-AzVMSize -Location $fakeBoundParameters['AzLocation']).Name
            $AzVMSizes | where-object {$_ -like "$wordToComplete*"} | foreach-Object { if ($_.contains(' ')) { "'" + $_ + "'" }else { $_ } }
        }
    )]
    [Parameter(Position = 1, Mandatory = $true)]
    [String]$AzVMSize,

    ##
    ## Azure Ressource Group
    ##
    [argumentcompleter({
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

            $resourceGroups = (Get-AzResourceGroup -Location $fakeBoundParameters['AzLocation']).ResourceGroupName
            $resourceGroups | where-object {$_ -like "$wordToComplete*"} | foreach-Object { if ($_.contains(' ')) { "'" + $_ + "'" }else { $_ } }
        }
    )]
    [Parameter(Position = 2, Mandatory = $true)]
    [String]$AzResourceGroup,

    ##
    ## Virtual Machine Name
    ##
    [String]$virtualMachineName,

    ##
    ## TineZone
    ##
    [argumentcompleter({
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

            $TimeZoneInfo = ([System.TimeZoneInfo]::GetSystemTimeZones()).iD
            $TimeZoneInfo | where-object {$_ -like "$wordToComplete*"} | foreach-Object { if ($_.contains(' ')) { "'" + $_ + "'" }else { $_ } }
        }
    )]
    [Parameter(Mandatory = $false)]
    [String]$VMTimeZone = 'W. Europe Standard Time',

    ##
    ## ImagePublisherName
    ##
    [argumentcompleter({
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

            $ImagePublisherName = (Get-AzVMImagePublisher -Location $fakeBoundParameters['AzLocation']).PublisherName
            $ImagePublisherName | where-object {$_ -like "$wordToComplete*"} | foreach-Object { if ($_.contains(' ')) { "'" + $_ + "'" }else { $_ } }
        }
    )]
    [Parameter(Mandatory = $false)]
    $AzImagePublisher = 'MicrosoftWindowsServer',

    ##
    ## ImageOffe
    ##
    [argumentcompleter({
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

            if([String]::isNullOrEmpty($fakeBoundParameters['ImagePublisherName'])){

                # If ImagePublishe not Set Use Microsoft Windows Server
                $fakeBoundParameters['ImagePublisherName'] = 'MicrosoftWindowsServer'
            }

            $ImageOffer = (Get-AzVMImageOffer  -Location ($fakeBoundParameters['AzLocation']) -PublisherName ($fakeBoundParameters['ImagePublisherName'])).Offer
            $ImageOffer | where-object {$_ -like "$wordToComplete*"} | foreach-Object { if ($_.contains(' ')) { "'" + $_ + "'" }else { $_ } }
        }
    )]
    [Parameter(Mandatory = $false)]
    $AzImageOffer = 'WindowsServer',

    ##
    ## ImageSKUs
    ##
    [argumentcompleter({
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

            if([String]::isNullOrEmpty($fakeBoundParameters['ImagePublisherName'])){

                # If ImagePublisher not Set Use Microsoft Windows Server
                $fakeBoundParameters['ImagePublisherName'] = 'MicrosoftWindowsServer'
            }

            if([String]::isNullOrEmpty($fakeBoundParameters['ImageOffer'])){

                # If ImageOffer not Set Use Microsoft WindowsServer
                $fakeBoundParameters['ImageOffer'] = 'WindowsServer'
            }

            $ImageSkus = (Get-AzVMImageSku  -Location $fakeBoundParameters['AzLocation'] -PublisherName $fakeBoundParameters['ImagePublisherName'] -Offer ($fakeBoundParameters['ImageOffer'] )).Skus
            $ImageSkus | where-object {$_ -like "$wordToComplete*"} | foreach-Object { if ($_.contains(' ')) { "'" + $_ + "'" }else { $_ } }
        }
    )]
    [Parameter(Mandatory = $true)]
    $AzImageSkus,

    [Parameter(Mandatory = $false)]
    $AzImageVersion = 'latest',

    ##
    ## Network Configuration
    ##
    [argumentcompleter({
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

            $virtualNetworkName = (Get-AzVirtualNetwork | Where-Object {$_.Location -eq $fakeBoundParameters['AzLocation']}).Name
            $virtualNetworkName | where-object {$_ -like "$wordToComplete*"} | foreach-Object { if ($_.contains(' ')) { "'" + $_ + "'" }else { $_ } }
        }
    )]
    [Parameter(Mandatory = $true)]
    [String]$AzVirtualNetwork,

    ##
    ## VirtualNetworkSubnet
    ##
    [argumentcompleter({
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

            $virtualNetworkName = (Get-AzVirtualNetwork | Where-Object {$_.Location -eq $fakeBoundParameters['AzLocation'] -and $_.Name -eq $fakeBoundParameters['virtualNetworkName']} | Get-AzVirtualNetworkSubnetConfig).name
            $virtualNetworkName | where-object {$_ -like "$wordToComplete*"} | foreach-Object { if ($_.contains(' ')) { "'" + $_ + "'" }else { $_ } }
        }
    )]
    [Parameter(Mandatory = $true)]
    [string]$AzVirtualNetworkSubnet,

    # VM Credentials
    [string]$LocalAdmin,
    [String]$LocalAdminPassword,

    #Domain Join
    [String]$JoinDomainName,
    [String]$JoinDomainOUPath,
    [String]$JoinDomainUser,
    [String]$JoinDomainUserPW
)

#
#region-----------------------------------------------------[Functions]------------------------------------------------------------
#

function New-VMNicNoPiP {
    
    param (

        [Parameter(Mandatory)]
        [String] $RessourceGroupName,

        [Parameter(Mandatory)]
        [String] $virtualNetworkName,

        [Parameter(Mandatory)]
        [String] $NameSubnet,

        [Parameter(Mandatory)]
        [String] $location,

        [Parameter(Mandatory)]
        [String] $NicName
    )

    #Get VNET Information
    $vNet = Get-AzVirtualNetwork -Name $virtualNetworkName
    $Subnet = Get-AzVirtualNetworkSubnetConfig -VirtualNetwork $vNet -Name $NameSubnet

    # Create NIC for the VM
    $Nic = New-AzNetworkInterface -Name $NicName -ResourceGroupName $RessourceGroupName -Location $location -SubnetId $subnet.Id -Force

    return $Nic
}

function Join-AzVMtoDomain {
    param (
        [String]$JoinDomainName,
        [String]$JoinDomainOUPath,
        [String]$JoinDomainUser,
        [String]$JoinDomainUserPW
    )

    $SettingsString = @{
        Name = $JoinDomainName
        User =  $JoinDomainUser
        OUPath = $JoinDomainOUPath
        Restart = "true"
        Options = "3"
    }

    $SettingsString = $SettingsString | ConvertTo-Json

    $ProtectedSettingsString = @{
        Password = $JoinDomainUserPW
    }

    $ProtectedSettingsString = $ProtectedSettingsString | ConvertTo-Json

    $result = Set-AzVMExtension `
                    -ResourceGroupName $AzResourceGroup `
                    -ExtensionType "JsonADDomainExtension" `
                    -Name "joindomain" `
                    -Publisher "Microsoft.Compute" `
                    -VMName $virtualMachineName `
                    -Location $AzLocation `
                    -SettingString $SettingsString `
                    -ProtectedSettingString $ProtectedSettingsString `
                    -TypeHandlerVersion "1.0"

    return $result
}

#
#endregion
#

#
#region----------------------------------------------------[Initialisations]--------------------------------------------------------
#

## 
## Select Azure Subscription
## 

Select-AzSubscription -SubscriptionId $AzSubscription


#
#endregion
#

$psCred = New-Object System.Management.Automation.PSCredential($LocalAdmin, (ConvertTo-SecureString $LocalAdminPassword -AsPlainText -Force))

#
#region------------------------------------------------------[Execution]------------------------------------------------------------
#

##
##Create Network Adapter
##

$VMNic = New-VMNicNoPiP -RessourceGroupName $AzResourceGroup -virtualNetworkName $AzVirtualNetwork -NameSubnet $AzVirtualNetworkSubnet -location $AzLocation -NicName ($VirtualMachineName.ToLower()+'_nic')

##
## Create Virtual Machine
##

$VirtualMachine = New-AzVMConfig -VMName $virtualMachineName -VMSize $AzVMSize
$VirtualMachine = Add-AzVMNetworkInterface -VM $VirtualMachine -Id $VMNic.ID
$VirtualMachine = Set-AzVMOperatingSystem -VM $virtualMachine -Windows -Credential $psCred -ComputerName $virtualMachineName -TimeZone $VMTimeZone
$virtualMachine = Set-AzVMSourceImage -VM $VirtualMachine -PublisherName $AzImagePublisher -Offer $AzImageOffer -Skus $AzImageSkus -Version $AzImageVersion

New-AzVM -VM $VirtualMachine -ResourceGroupName $AzResourceGroup -Location $AzLocation

##
## Domain Join
##

if(!([String]::isNullOrEmpty($JoinDomainName))){

    Join-AzVMtoDomain -JoinDomainName $JoinDomainName -JoinDomainOUPath $JoinDomainOUPath -JoinDomainUser $JoinDomainUser -JoinDomainUserPW $JoinDomainUserPW
}

#
#endregion
#