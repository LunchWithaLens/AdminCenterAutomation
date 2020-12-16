<#
.SYNOPSIS
    Select the closest match from local session cache based on the client application parameters provided and create one if there is no match.
.DESCRIPTION
    This cmdlet should only be used if you want to store your client application in the local session cache.
.EXAMPLE
    PS C:\>Select-MsalClientApplication -ClientId '00000000-0000-0000-0000-000000000000'
    Select a public client application from local session cache with client id 00000000-0000-0000-0000-000000000000 and default settings.
#>
function Select-MsalClientApplication {
    [CmdletBinding(DefaultParameterSetName = 'PublicClient')]
    [OutputType([Microsoft.Identity.Client.PublicClientApplication], [Microsoft.Identity.Client.ConfidentialClientApplication])]
    param
    (
        # Identifier of the client requesting the token.
        [Parameter(Mandatory = $true, ParameterSetName = 'PublicClient', Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $false, ParameterSetName = 'PublicClient-InputObject', Position = 1, ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = 'ConfidentialClientSecret', Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = 'ConfidentialClientCertificate', Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $false, ParameterSetName = 'ConfidentialClient-InputObject', Position = 1, ValueFromPipelineByPropertyName = $true)]
        [string] $ClientId,
        # Secure secret of the client requesting the token.
        [Parameter(Mandatory = $true, ParameterSetName = 'ConfidentialClientSecret', ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $false, ParameterSetName = 'ConfidentialClient-InputObject', ValueFromPipelineByPropertyName = $true)]
        #[AllowNull()]
        [securestring] $ClientSecret,
        # Client assertion certificate of the client requesting the token.
        [Parameter(Mandatory = $true, ParameterSetName = 'ConfidentialClientCertificate', ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $false, ParameterSetName = 'ConfidentialClient-InputObject', ValueFromPipelineByPropertyName = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $ClientCertificate,
        # Address to return to upon receiving a response from the authority.
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [uri] $RedirectUri,
        # Instance of Azure Cloud
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [Microsoft.Identity.Client.AzureCloudInstance] $AzureCloudInstance,
        # Tenant identifier of the authority to issue token.
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string] $TenantId,
        # Address of the authority to issue token.
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [uri] $Authority,
        # Public client application options
        [Parameter(Mandatory = $true, ParameterSetName = 'PublicClient-InputObject', Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Microsoft.Identity.Client.PublicClientApplicationOptions] $PublicClientOptions,
        # Confidential client application options
        [Parameter(Mandatory = $true, ParameterSetName = 'ConfidentialClient-InputObject', Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Microsoft.Identity.Client.ConfidentialClientApplicationOptions] $ConfidentialClientOptions
    )

    $paramNewMsalClientApplication = Select-PsBoundParameters $PSBoundParameters -CommandName New-MsalClientApplication -ExcludeParameters ErrorAction
    $NewClientApplication = New-MsalClientApplication -ErrorAction Stop @paramNewMsalClientApplication
    switch -Wildcard ($PSCmdlet.ParameterSetName) {
        "PublicClient*" {
            #[Microsoft.Identity.Client.IPublicClientApplication] $ClientApplication = $PublicClientApplications | Where-Object { $_.ClientId -eq $NewClientApplication.ClientId -and $_.AppConfig.RedirectUri -eq $NewClientApplication.AppConfig.RedirectUri -and $_.AppConfig.TenantId -eq $NewClientApplication.AppConfig.TenantId } | Select-Object -Last 1
            [Microsoft.Identity.Client.IPublicClientApplication] $ClientApplication = $PublicClientApplications | Where-Object { $_.ClientId -eq $NewClientApplication.ClientId -and $_.AppConfig.RedirectUri -eq $NewClientApplication.AppConfig.RedirectUri } | Select-Object -Last 1
            break
        }
        "ConfidentialClientSecret" {
            #[Microsoft.Identity.Client.IConfidentialClientApplication] $ClientApplication = $ConfidentialClientApplications | Where-Object { $_.ClientId -eq $NewClientApplication.ClientId -and $_.AppConfig.ClientSecret -eq $NewClientApplication.AppConfig.ClientSecret -and $_.AppConfig.RedirectUri -eq $NewClientApplication.AppConfig.RedirectUri -and $_.AppConfig.TenantId -eq $NewClientApplication.AppConfig.TenantId } | Select-Object -Last 1
            [Microsoft.Identity.Client.IConfidentialClientApplication] $ClientApplication = $ConfidentialClientApplications | Where-Object { $_.ClientId -eq $NewClientApplication.ClientId -and $_.AppConfig.ClientSecret -eq $NewClientApplication.AppConfig.ClientSecret -and $_.AppConfig.RedirectUri -eq $NewClientApplication.AppConfig.RedirectUri } | Select-Object -Last 1
            break
        }
        "ConfidentialClientCertificate" {
            #[Microsoft.Identity.Client.IConfidentialClientApplication] $ClientApplication = $ConfidentialClientApplications | Where-Object { $_.ClientId -eq $NewClientApplication.ClientId -and $_.AppConfig.ClientCredentialCertificate -eq $NewClientApplication.AppConfig.ClientCredentialCertificate -and $_.AppConfig.RedirectUri -eq $NewClientApplication.AppConfig.RedirectUri -and $_.AppConfig.TenantId -eq $NewClientApplication.AppConfig.TenantId } | Select-Object -Last 1
            [Microsoft.Identity.Client.IConfidentialClientApplication] $ClientApplication = $ConfidentialClientApplications | Where-Object { $_.ClientId -eq $NewClientApplication.ClientId -and $_.AppConfig.ClientCredentialCertificate -eq $NewClientApplication.AppConfig.ClientCredentialCertificate -and $_.AppConfig.RedirectUri -eq $NewClientApplication.AppConfig.RedirectUri } | Select-Object -Last 1
            break
        }
        "ConfidentialClient-InputObject" {
            if ($NewClientApplication.AppConfig.ClientSecret) {
                #[Microsoft.Identity.Client.IConfidentialClientApplication] $ClientApplication = $ConfidentialClientApplications | Where-Object { $_.ClientId -eq $NewClientApplication.ClientId -and $_.AppConfig.ClientSecret -eq $NewClientApplication.AppConfig.ClientSecret -and $_.AppConfig.RedirectUri -eq $NewClientApplication.AppConfig.RedirectUri -and $_.AppConfig.TenantId -eq $NewClientApplication.AppConfig.TenantId } | Select-Object -Last 1
                [Microsoft.Identity.Client.IConfidentialClientApplication] $ClientApplication = $ConfidentialClientApplications | Where-Object { $_.ClientId -eq $NewClientApplication.ClientId -and $_.AppConfig.ClientSecret -eq $NewClientApplication.AppConfig.ClientSecret -and $_.AppConfig.RedirectUri -eq $NewClientApplication.AppConfig.RedirectUri } | Select-Object -Last 1
            }
            else {
                #[Microsoft.Identity.Client.IConfidentialClientApplication] $ClientApplication = $ConfidentialClientApplications | Where-Object { $_.ClientId -eq $NewClientApplication.ClientId -and $_.AppConfig.ClientCredentialCertificate -eq $NewClientApplication.AppConfig.ClientCredentialCertificate -and $_.AppConfig.RedirectUri -eq $NewClientApplication.AppConfig.RedirectUri -and $_.AppConfig.TenantId -eq $NewClientApplication.AppConfig.TenantId } | Select-Object -Last 1
                [Microsoft.Identity.Client.IConfidentialClientApplication] $ClientApplication = $ConfidentialClientApplications | Where-Object { $_.ClientId -eq $NewClientApplication.ClientId -and $_.AppConfig.ClientCredentialCertificate -eq $NewClientApplication.AppConfig.ClientCredentialCertificate -and $_.AppConfig.RedirectUri -eq $NewClientApplication.AppConfig.RedirectUri } | Select-Object -Last 1
            }
            break
        }
    }

    if (!$ClientApplication) {
        $ClientApplication = $NewClientApplication
        Write-Debug ('Adding Application with ClientId [{0}] and RedirectUri [{1}] to cache.' -f $ClientApplication.AppConfig.ClientId, $ClientApplication.AppConfig.RedirectUri)
        Add-MsalClientApplication $ClientApplication
    }
    else {
        Write-Debug ('Using Application with ClientId [{0}] and RedirectUri [{1}] from cache.' -f $ClientApplication.AppConfig.ClientId, $ClientApplication.AppConfig.RedirectUri)
    }

    return $ClientApplication
}

# SIG # Begin signature block
# MIIckwYJKoZIhvcNAQcCoIIchDCCHIACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAZBM/0dkR8KKKM
# u+8ICoJnkCeGBA9WDQcBKa95L+u34qCCF50wggUmMIIEDqADAgECAhAKbwamSf02
# TrzqY8wkoMRzMA0GCSqGSIb3DQEBCwUAMHIxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xMTAvBgNV
# BAMTKERpZ2lDZXJ0IFNIQTIgQXNzdXJlZCBJRCBDb2RlIFNpZ25pbmcgQ0EwHhcN
# MjAwMzMxMDAwMDAwWhcNMjMwNDA1MTIwMDAwWjBjMQswCQYDVQQGEwJVUzENMAsG
# A1UECBMET2hpbzETMBEGA1UEBxMKQ2luY2lubmF0aTEXMBUGA1UEChMOSmFzb24g
# VGhvbXBzb24xFzAVBgNVBAMTDkphc29uIFRob21wc29uMIIBIjANBgkqhkiG9w0B
# AQEFAAOCAQ8AMIIBCgKCAQEAxWfKBk7TC+lDc2MakRESqnSv8U3kLRfQafofGuE9
# cDIZloGUSNXR47pvPw0FUXDIexDQEXFPsKsa8ILC96Sbtuohlogl72QVgC85UEMr
# 5LTjZ0ZpPxxRLFTpAiSBcvYhkpm7xHwfT7bqt6Ealp2P6idurMWyFpLwLXz/WgW/
# btb/cV47ACRdsTwxum5z2e1H/o9RXhuLDcBhQhNWmzQ+Z9MHV/ToOattZreisdUM
# 7XIQv8TWGh7SOlc8AfO+02Usy1mDkt5GsZ2R9qyrxX3heJw1ZTxcXLoPlwWUiDRE
# 9xLMwlElvvyd+lAieukMBqC+IMJRVHlnAuy8OTT3qHyQJQIDAQABo4IBxTCCAcEw
# HwYDVR0jBBgwFoAUWsS5eyoKo6XqcQPAYPkt9mV1DlgwHQYDVR0OBBYEFL7nzjkk
# +8NZ6eNdqEujhdQJxOcyMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEF
# BQcDAzB3BgNVHR8EcDBuMDWgM6Axhi9odHRwOi8vY3JsMy5kaWdpY2VydC5jb20v
# c2hhMi1hc3N1cmVkLWNzLWcxLmNybDA1oDOgMYYvaHR0cDovL2NybDQuZGlnaWNl
# cnQuY29tL3NoYTItYXNzdXJlZC1jcy1nMS5jcmwwTAYDVR0gBEUwQzA3BglghkgB
# hv1sAwEwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQ
# UzAIBgZngQwBBAEwgYQGCCsGAQUFBwEBBHgwdjAkBggrBgEFBQcwAYYYaHR0cDov
# L29jc3AuZGlnaWNlcnQuY29tME4GCCsGAQUFBzAChkJodHRwOi8vY2FjZXJ0cy5k
# aWdpY2VydC5jb20vRGlnaUNlcnRTSEEyQXNzdXJlZElEQ29kZVNpZ25pbmdDQS5j
# cnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEARH2swe77D6omtCaH
# pq3oasA9i4eLbO5TTid1FHNNKYdQq/NLUO8RjEunpw7//eAcSoFXVLRhXnxGfmJ0
# yKLt+YA1J87U6DjHvv8KaaenAHxqhIKltHGpwgET6lSbuvskFPjE0QpPcWSBylXK
# YThW4ixwGCd6QSaZpV8OiHVebhxD6G+3Jnz7f5s1D857TTxFKTnOaJaJL754Z4HU
# Pm/rIuzZscAeV0ooKnwyDfbZWpEHYL1sWVBLFL3sUH+zgniMbGNJKXoyZxgvOTD4
# Kilzn/1zVATMF772tkxoA/Bvp73vu2QW0U4J+J6QRICOS7Y0+qOPzcS0s46WWu/e
# vzWhZzCCBTAwggQYoAMCAQICEAQJGBtf1btmdVNDtW+VUAgwDQYJKoZIhvcNAQEL
# BQAwZTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UE
# CxMQd3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UEAxMbRGlnaUNlcnQgQXNzdXJlZCBJ
# RCBSb290IENBMB4XDTEzMTAyMjEyMDAwMFoXDTI4MTAyMjEyMDAwMFowcjELMAkG
# A1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRp
# Z2ljZXJ0LmNvbTExMC8GA1UEAxMoRGlnaUNlcnQgU0hBMiBBc3N1cmVkIElEIENv
# ZGUgU2lnbmluZyBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPjT
# sxx/DhGvZ3cH0wsxSRnP0PtFmbE620T1f+Wondsy13Hqdp0FLreP+pJDwKX5idQ3
# Gde2qvCchqXYJawOeSg6funRZ9PG+yknx9N7I5TkkSOWkHeC+aGEI2YSVDNQdLEo
# JrskacLCUvIUZ4qJRdQtoaPpiCwgla4cSocI3wz14k1gGL6qxLKucDFmM3E+rHCi
# q85/6XzLkqHlOzEcz+ryCuRXu0q16XTmK/5sy350OTYNkO/ktU6kqepqCquE86xn
# TrXE94zRICUj6whkPlKWwfIPEvTFjg/BougsUfdzvL2FsWKDc0GCB+Q4i2pzINAP
# ZHM8np+mM6n9Gd8lk9ECAwEAAaOCAc0wggHJMBIGA1UdEwEB/wQIMAYBAf8CAQAw
# DgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMDMHkGCCsGAQUFBwEB
# BG0wazAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsG
# AQUFBzAChjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1
# cmVkSURSb290Q0EuY3J0MIGBBgNVHR8EejB4MDqgOKA2hjRodHRwOi8vY3JsNC5k
# aWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMDqgOKA2hjRo
# dHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0Eu
# Y3JsME8GA1UdIARIMEYwOAYKYIZIAYb9bAACBDAqMCgGCCsGAQUFBwIBFhxodHRw
# czovL3d3dy5kaWdpY2VydC5jb20vQ1BTMAoGCGCGSAGG/WwDMB0GA1UdDgQWBBRa
# xLl7KgqjpepxA8Bg+S32ZXUOWDAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd
# 823IDzANBgkqhkiG9w0BAQsFAAOCAQEAPuwNWiSz8yLRFcgsfCUpdqgdXRwtOhrE
# 7zBh134LYP3DPQ/Er4v97yrfIFU3sOH20ZJ1D1G0bqWOWuJeJIFOEKTuP3GOYw4T
# S63XX0R58zYUBor3nEZOXP+QsRsHDpEV+7qvtVHCjSSuJMbHJyqhKSgaOnEoAjwu
# kaPAJRHinBRHoXpoaK+bp1wgXNlxsQyPu6j4xRJon89Ay0BEpRPw5mQMJQhCMrI2
# iiQC/i9yfhzXSUWW6Fkd6fp0ZGuy62ZD2rOwjNXpDd32ASDOmTFjPQgaGLOBm0/G
# kxAG/AeB+ova+YJJ92JuoVP6EpQYhS6SkepobEQysmah5xikmmRR7zCCBmowggVS
# oAMCAQICEAMBmgI6/1ixa9bV6uYX8GYwDQYJKoZIhvcNAQEFBQAwYjELMAkGA1UE
# BhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2lj
# ZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgQXNzdXJlZCBJRCBDQS0xMB4XDTE0
# MTAyMjAwMDAwMFoXDTI0MTAyMjAwMDAwMFowRzELMAkGA1UEBhMCVVMxETAPBgNV
# BAoTCERpZ2lDZXJ0MSUwIwYDVQQDExxEaWdpQ2VydCBUaW1lc3RhbXAgUmVzcG9u
# ZGVyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo2Rd/Hyz4II14OD2
# xirmSXU7zG7gU6mfH2RZ5nxrf2uMnVX4kuOe1VpjWwJJUNmDzm9m7t3LhelfpfnU
# h3SIRDsZyeX1kZ/GFDmsJOqoSyyRicxeKPRktlC39RKzc5YKZ6O+YZ+u8/0SeHUO
# plsU/UUjjoZEVX0YhgWMVYd5SEb3yg6Np95OX+Koti1ZAmGIYXIYaLm4fO7m5zQv
# MXeBMB+7NgGN7yfj95rwTDFkjePr+hmHqH7P7IwMNlt6wXq4eMfJBi5GEMiN6ARg
# 27xzdPpO2P6qQPGyznBGg+naQKFZOtkVCVeZVjCT88lhzNAIzGvsYkKRrALA76Tw
# iRGPdwIDAQABo4IDNTCCAzEwDgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAw
# FgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwggG/BgNVHSAEggG2MIIBsjCCAaEGCWCG
# SAGG/WwHATCCAZIwKAYIKwYBBQUHAgEWHGh0dHBzOi8vd3d3LmRpZ2ljZXJ0LmNv
# bS9DUFMwggFkBggrBgEFBQcCAjCCAVYeggFSAEEAbgB5ACAAdQBzAGUAIABvAGYA
# IAB0AGgAaQBzACAAQwBlAHIAdABpAGYAaQBjAGEAdABlACAAYwBvAG4AcwB0AGkA
# dAB1AHQAZQBzACAAYQBjAGMAZQBwAHQAYQBuAGMAZQAgAG8AZgAgAHQAaABlACAA
# RABpAGcAaQBDAGUAcgB0ACAAQwBQAC8AQwBQAFMAIABhAG4AZAAgAHQAaABlACAA
# UgBlAGwAeQBpAG4AZwAgAFAAYQByAHQAeQAgAEEAZwByAGUAZQBtAGUAbgB0ACAA
# dwBoAGkAYwBoACAAbABpAG0AaQB0ACAAbABpAGEAYgBpAGwAaQB0AHkAIABhAG4A
# ZAAgAGEAcgBlACAAaQBuAGMAbwByAHAAbwByAGEAdABlAGQAIABoAGUAcgBlAGkA
# bgAgAGIAeQAgAHIAZQBmAGUAcgBlAG4AYwBlAC4wCwYJYIZIAYb9bAMVMB8GA1Ud
# IwQYMBaAFBUAEisTmLKZB+0e36K+Vw0rZwLNMB0GA1UdDgQWBBRhWk0ktkkynUoq
# eRqDS/QeicHKfTB9BgNVHR8EdjB0MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2Vy
# dC5jb20vRGlnaUNlcnRBc3N1cmVkSURDQS0xLmNybDA4oDagNIYyaHR0cDovL2Ny
# bDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEQ0EtMS5jcmwwdwYIKwYB
# BQUHAQEEazBpMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20w
# QQYIKwYBBQUHMAKGNWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2Vy
# dEFzc3VyZWRJRENBLTEuY3J0MA0GCSqGSIb3DQEBBQUAA4IBAQCdJX4bM02yJoFc
# m4bOIyAPgIfliP//sdRqLDHtOhcZcRfNqRu8WhY5AJ3jbITkWkD73gYBjDf6m7Gd
# JH7+IKRXrVu3mrBgJuppVyFdNC8fcbCDlBkFazWQEKB7l8f2P+fiEUGmvWLZ8Cc9
# OB0obzpSCfDscGLTYkuw4HOmksDTjjHYL+NtFxMG7uQDthSr849Dp3GdId0UyhVd
# kkHa+Q+B0Zl0DSbEDn8btfWg8cZ3BigV6diT5VUW8LsKqxzbXEgnZsijiwoc5ZXa
# rsQuWaBh3drzbaJh6YoLbewSGL33VVRAA5Ira8JRwgpIr7DUbuD0FAo6G+OPPcqv
# ao173NhEMIIGzTCCBbWgAwIBAgIQBv35A5YDreoACus/J7u6GzANBgkqhkiG9w0B
# AQUFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVk
# IElEIFJvb3QgQ0EwHhcNMDYxMTEwMDAwMDAwWhcNMjExMTEwMDAwMDAwWjBiMQsw
# CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
# ZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBBc3N1cmVkIElEIENBLTEw
# ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDogi2Z+crCQpWlgHNAcNKe
# VlRcqcTSQQaPyTP8TUWRXIGf7Syc+BZZ3561JBXCmLm0d0ncicQK2q/LXmvtrbBx
# MevPOkAMRk2T7It6NggDqww0/hhJgv7HxzFIgHweog+SDlDJxofrNj/YMMP/pvf7
# os1vcyP+rFYFkPAyIRaJxnCI+QWXfaPHQ90C6Ds97bFBo+0/vtuVSMTuHrPyvAwr
# mdDGXRJCgeGDboJzPyZLFJCuWWYKxI2+0s4Grq2Eb0iEm09AufFM8q+Y+/bOQF1c
# 9qjxL6/siSLyaxhlscFzrdfx2M8eCnRcQrhofrfVdwonVnwPYqQ/MhRglf0HBKIJ
# AgMBAAGjggN6MIIDdjAOBgNVHQ8BAf8EBAMCAYYwOwYDVR0lBDQwMgYIKwYBBQUH
# AwEGCCsGAQUFBwMCBggrBgEFBQcDAwYIKwYBBQUHAwQGCCsGAQUFBwMIMIIB0gYD
# VR0gBIIByTCCAcUwggG0BgpghkgBhv1sAAEEMIIBpDA6BggrBgEFBQcCARYuaHR0
# cDovL3d3dy5kaWdpY2VydC5jb20vc3NsLWNwcy1yZXBvc2l0b3J5Lmh0bTCCAWQG
# CCsGAQUFBwICMIIBVh6CAVIAQQBuAHkAIAB1AHMAZQAgAG8AZgAgAHQAaABpAHMA
# IABDAGUAcgB0AGkAZgBpAGMAYQB0AGUAIABjAG8AbgBzAHQAaQB0AHUAdABlAHMA
# IABhAGMAYwBlAHAAdABhAG4AYwBlACAAbwBmACAAdABoAGUAIABEAGkAZwBpAEMA
# ZQByAHQAIABDAFAALwBDAFAAUwAgAGEAbgBkACAAdABoAGUAIABSAGUAbAB5AGkA
# bgBnACAAUABhAHIAdAB5ACAAQQBnAHIAZQBlAG0AZQBuAHQAIAB3AGgAaQBjAGgA
# IABsAGkAbQBpAHQAIABsAGkAYQBiAGkAbABpAHQAeQAgAGEAbgBkACAAYQByAGUA
# IABpAG4AYwBvAHIAcABvAHIAYQB0AGUAZAAgAGgAZQByAGUAaQBuACAAYgB5ACAA
# cgBlAGYAZQByAGUAbgBjAGUALjALBglghkgBhv1sAxUwEgYDVR0TAQH/BAgwBgEB
# /wIBADB5BggrBgEFBQcBAQRtMGswJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRp
# Z2ljZXJ0LmNvbTBDBggrBgEFBQcwAoY3aHR0cDovL2NhY2VydHMuZGlnaWNlcnQu
# Y29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNydDCBgQYDVR0fBHoweDA6oDig
# NoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9v
# dENBLmNybDA6oDigNoY0aHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0
# QXNzdXJlZElEUm9vdENBLmNybDAdBgNVHQ4EFgQUFQASKxOYspkH7R7for5XDStn
# As0wHwYDVR0jBBgwFoAUReuir/SSy4IxLVGLp6chnfNtyA8wDQYJKoZIhvcNAQEF
# BQADggEBAEZQPsm3KCSnOB22WymvUs9S6TFHq1Zce9UNC0Gz7+x1H3Q48rJcYaKc
# lcNQ5IK5I9G6OoZyrTh4rHVdFxc0ckeFlFbR67s2hHfMJKXzBBlVqefj56tizfuL
# LZDCwNK1lL1eT7EF0g49GqkUW6aGMWKoqDPkmzmnxPXOHXh2lCVz5Cqrz5x2S+1f
# wksW5EtwTACJHvzFebxMElf+X+EevAJdqP77BzhPDcZdkbkPZ0XN1oPt55INjbFp
# jE/7WeAjD9KqrgB87pxCDs+R1ye3Fu4Pw718CqDuLAhVhSK46xgaTfwqIa1JMYNH
# lXdx3LEbS0scEJx3FMGdTy9alQgpECYxggRMMIIESAIBATCBhjByMQswCQYDVQQG
# EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNl
# cnQuY29tMTEwLwYDVQQDEyhEaWdpQ2VydCBTSEEyIEFzc3VyZWQgSUQgQ29kZSBT
# aWduaW5nIENBAhAKbwamSf02TrzqY8wkoMRzMA0GCWCGSAFlAwQCAQUAoIGEMBgG
# CisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcC
# AQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIE
# IJFq9NplsLCuM8+9Po4IV9/ifH7rtwvTQCTpDvqaSO0vMA0GCSqGSIb3DQEBAQUA
# BIIBALpWhsrVzXZDxxZQ9ZLLF0V4yIKjy/65MFOsYyo1/KJ/3AFe79x0HbXznl+K
# ZQ/3AwgM0X2ZG4jz1ZZ8Xbb+6u2SbrYSQCjnuXXN0KdQHMmOEwjw2ZgnuWp4EKGL
# oXzbQBoTH2fxheJpHRPbHwXA3+HkbhpV9mt3MJ3My/HXXnVaNKaXLE+HMKV31uBu
# N7M6MCDExnHO6mbtMRYtLximc7TeA1OZoJ/4esRl4vtHcqGQau5GFeVAQMzdH3X9
# JV1M6Vcpl8ELSKjfslbFggJ642Ulm/WjALFRTttBbP9fwE4XgU7Iui2obgt7RwOP
# ks0GDOYt6cqstRnkgSf5iMhz26mhggIPMIICCwYJKoZIhvcNAQkGMYIB/DCCAfgC
# AQEwdjBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBBc3N1cmVk
# IElEIENBLTECEAMBmgI6/1ixa9bV6uYX8GYwCQYFKw4DAhoFAKBdMBgGCSqGSIb3
# DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTIwMDgxODIyNTkwOFow
# IwYJKoZIhvcNAQkEMRYEFF/UyEGhJoeSvCiRNAhN6W2G+ZS6MA0GCSqGSIb3DQEB
# AQUABIIBABGZS5lcPCbgxWUeLlmNaeKPpGdwq5IvAnl1cm9osdO0zAHBrh+Odmx/
# TGX629AtjSLJkDPjIoUbix3qdVI8g4bk+HMTyV0zprw5sH0DO2Ez96LZ2kBLn/Sj
# is81QX5V1bZLbgn/dveumiatYraCl5ceQEoRVX8Ygah6/bLhSYs55+anr3UM+aNg
# 9g3T611wvxUXY4X6Ju2HtNSo/9v2WmiqCv8iuMtzjSkQdyzmuOTo52i0kK9Gl/6y
# g1CqRoAhi/UP+fcqkLt2mZDIb8h6akFrJKRT2txKMZjjSO7lck+ecODQGawPmRU7
# PEtPOjjqPBeEOY8Q4TJ31uoxWzAWb4k=
# SIG # End signature block
