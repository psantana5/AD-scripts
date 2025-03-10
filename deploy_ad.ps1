# Script de PowerShell para la configuración del dominio, usuarios, recursos compartidos, 
# directivas, DHCP y WSUS según los requisitos especificados

# ------------------------------------------------------------------------------
# 1. Configuración del Controlador de Dominio Active Directory
# ------------------------------------------------------------------------------

# Definir nombre del dominio 
$nombreDominio = "PrecisionIT.com"

# Comprobar si el dominio ya está desplegado
$isDomainController = $false
try {
    $domainInfo = Get-ADDomain -Identity $nombreDominio.Split('.')[0] -ErrorAction Stop
    $isDomainController = $true
    Write-Host "El dominio $nombreDominio ya está desplegado. Omitiendo la instalación del controlador de dominio." -ForegroundColor Yellow
} catch {
    Write-Host "El dominio $nombreDominio no está desplegado. Procediendo con la instalación." -ForegroundColor Green
}

if (-not $isDomainController) {
    # Instalar el rol de AD DS
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

    # Importar el módulo de AD DS
    Import-Module ADDSDeployment

    # Promover el servidor a controlador de dominio
    Install-ADDSForest `
        -CreateDnsDelegation:$false `
        -DatabasePath "C:\Windows\NTDS" `
        -DomainMode "WinThreshold" `
        -DomainName $nombreDominio `
        -ForestMode "WinThreshold" `
        -InstallDns:$true `
        -LogPath "C:\Windows\NTDS" `
        -NoRebootOnCompletion:$false `
        -SysvolPath "C:\Windows\SYSVOL" `
        -Force:$true
}

# ------------------------------------------------------------------------------
# 2. Creación de usuarios administradores para cada miembro del grupo
# ------------------------------------------------------------------------------

# Definir los nombres de los miembros del grupo.
$miembrosGrupo = @("psantana")

foreach ($miembro in $miembrosGrupo) {
    $usuarioAdmin = $miembro
    $contraseniaAdmin = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force
    
    # Crear usuario administrador
    New-ADUser `
        -Name $usuarioAdmin `
        -GivenName $usuarioAdmin `
        -SamAccountName $usuarioAdmin `
        -UserPrincipalName "$usuarioAdmin@$nombreDominio" `
        -AccountPassword $contraseniaAdmin `
        -Enabled $true `
        -PasswordNeverExpires $true

    # Añadir al grupo de administradores del dominio
    Add-ADGroupMember -Identity "Domain Admins" -Members $usuarioAdmin
}

# ------------------------------------------------------------------------------
# 3. Creación masiva de usuarios desde un archivo CSV
# ------------------------------------------------------------------------------

# Estructura esperada del CSV:
# Nombre,Apellido,Usuario,Departamento,Email
# Juan,Perez,jperez,Ventas,jperez@tuorg.com
# ...

# Crear el directorio para el CSV si no existe
$csvPath = "C:\Scripts"
if (-not (Test-Path -Path $csvPath)) {
    New-Item -ItemType Directory -Path $csvPath -Force
}

# Generar el archivo CSV de ejemplo con 60 usuarios (30 para cada departamento)
$csvContent = @"
Nombre,Apellido,Usuario,Departamento,Email
"@

# Generar 30 usuarios para el departamento IT
for ($i = 1; $i -le 30; $i++) {
    $csvContent += "`nEmpleado$i,Apellido$i,emp$i,IT,emp$i@$nombreDominio"
}

# Generar 30 usuarios para el departamento RRHH
for ($i = 31; $i -le 60; $i++) {
    $csvContent += "`nEmpleado$i,Apellido$i,emp$i,RRHH,emp$i@$nombreDominio"
}

# Guardar el archivo CSV
$csvFile = Join-Path -Path $csvPath -ChildPath "usuarios.csv"
$csvContent | Out-File -FilePath $csvFile -Encoding UTF8

# Crear usuarios a partir del CSV
$usuarios = Import-Csv -Path $csvFile
foreach ($usuario in $usuarios) {
    $contrasena = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force
    
    # Crear el usuario
    New-ADUser `
        -Name "$($usuario.Nombre) $($usuario.Apellido)" `
        -GivenName $usuario.Nombre `
        -Surname $usuario.Apellido `
        -SamAccountName $usuario.Usuario `
        -UserPrincipalName "$($usuario.Usuario)@$nombreDominio" `
        -EmailAddress $usuario.Email `
        -Department $usuario.Departamento `
        -AccountPassword $contrasena `
        -Enabled $true `
        -ChangePasswordAtLogon $true
}

# ------------------------------------------------------------------------------
# 4. Creación de grupos para los departamentos
# ------------------------------------------------------------------------------

# Crear los grupos para los departamentos
New-ADGroup -Name "IT" -GroupScope Global -GroupCategory Security
New-ADGroup -Name "RRHH" -GroupScope Global -GroupCategory Security

# Asignar usuarios a los grupos correspondientes
$usuarios = Import-Csv -Path $csvFile
foreach ($usuario in $usuarios) {
    if ($usuario.Departamento -eq "IT") {
        Add-ADGroupMember -Identity "IT" -Members $usuario.Usuario
    }
    elseif ($usuario.Departamento -eq "RRHH") {
        Add-ADGroupMember -Identity "RRHH" -Members $usuario.Usuario
    }
}

# ------------------------------------------------------------------------------
# 5. Creación de recursos compartidos
# ------------------------------------------------------------------------------

# Crear directorios para los recursos compartidos
$compartidoDep1 = "C:\Compartidos\IT"
$compartidoDep2 = "C:\Compartidos\RRHH"

New-Item -Path $compartidoDep1 -ItemType Directory -Force
New-Item -Path $compartidoDep2 -ItemType Directory -Force

# Crear los recursos compartidos con permisos adecuados
New-SmbShare -Name "IT" -Path $compartidoDep1 -FullAccess "DOMAIN ADMINS", "IT" -NoAccess "Everyone"
New-SmbShare -Name "RRHH" -Path $compartidoDep2 -FullAccess "DOMAIN ADMINS", "RRHH" -NoAccess "Everyone"

# Asignar permisos de NTFS
$acl1 = Get-Acl -Path $compartidoDep1
$acl2 = Get-Acl -Path $compartidoDep2

# Limpiar permisos heredados
$acl1.SetAccessRuleProtection($true, $false)
$acl2.SetAccessRuleProtection($true, $false)

# Añadir permiso para System y Administradores
$regla = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl1.AddAccessRule($regla)
$acl2.AddAccessRule($regla)

$regla = New-Object System.Security.AccessControl.FileSystemAccessRule("DOMAIN ADMINS", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl1.AddAccessRule($regla)
$acl2.AddAccessRule($regla)

# Añadir permisos para los grupos de departamento
$regla = New-Object System.Security.AccessControl.FileSystemAccessRule("IT", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl1.AddAccessRule($regla)

$regla = New-Object System.Security.AccessControl.FileSystemAccessRule("RRHH", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl2.AddAccessRule($regla)

# Aplicar los permisos
Set-Acl -Path $compartidoDep1 -AclObject $acl1
Set-Acl -Path $compartidoDep2 -AclObject $acl2

# ------------------------------------------------------------------------------
# 6. Configuración de directivas de dominio
# ------------------------------------------------------------------------------

# Importar el módulo de directivas de grupo
Import-Module GroupPolicy

# Crear una nueva GPO
$gpoName = "Política de Seguridad"
New-GPO -Name $gpoName

# Configurar historial de contraseñas (12 en lugar de 24)
Set-GPRegistryValue -Name $gpoName -Key "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" -ValueName "PasswordHistorySize" -Type DWord -Value 12

# Configurar política de bloqueo de cuenta
# Bloqueo tras 3 intentos fallidos
Set-GPRegistryValue -Name $gpoName -Key "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" -ValueName "BadLoginAttempts" -Type DWord -Value 3

# Bloqueo durante 60 minutos (3600 segundos)
Set-GPRegistryValue -Name $gpoName -Key "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" -ValueName "LockoutDuration" -Type DWord -Value 3600

# Restablecimiento del contador tras 60 segundos
Set-GPRegistryValue -Name $gpoName -Key "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" -ValueName "ResetLockoutCount" -Type DWord -Value 60

# Mostrar información de inicios de sesión anteriores
Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "DisplayLastLogonInfo" -Type DWord -Value 1

# Aplicar la GPO al dominio
New-GPLink -Name $gpoName -Target "DC=$($nombreDominio.Split('.')[0]),DC=$($nombreDominio.Split('.')[1])"

# ------------------------------------------------------------------------------
# 7. Instalación y configuración del servidor DHCP
# ------------------------------------------------------------------------------

# Instalar el rol de DHCP
Install-WindowsFeature -Name DHCP -IncludeManagementTools

# Autorizar el servidor DHCP en Active Directory
Add-DhcpServerInDC

# Configurar ámbitos DHCP según el plan de direccionamiento

# Función para verificar si un ámbito ya existe
function Test-DhcpScope {
    param (
        [string]$ScopeId
    )
    
    try {
        $scope = Get-DhcpServerv4Scope -ScopeId $ScopeId -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

# VLAN 10 (Gerencia/RRHH)
if (-not (Test-DhcpScope -ScopeId "192.168.0.0")) {
    Write-Host "Creando ámbito DHCP para VLAN 10 - Gerencia/RRHH" -ForegroundColor Green
    Add-DhcpServerv4Scope -Name "VLAN 10 - Gerencia/RRHH" -StartRange 192.168.0.50 -EndRange 192.168.0.200 -SubnetMask 255.255.255.0
} else {
    Write-Host "El ámbito DHCP para VLAN 10 - Gerencia/RRHH ya existe" -ForegroundColor Yellow
}

# Configurar opciones de ámbito para VLAN 10
Set-DhcpServerv4OptionValue -ScopeId 192.168.0.0 -Router 192.168.0.1 -DnsDomain $nombreDominio -DnsServer 192.168.3.50

# VLAN 20 (Diseño)
if (-not (Test-DhcpScope -ScopeId "192.168.1.0")) {
    Write-Host "Creando ámbito DHCP para VLAN 20 - Diseño" -ForegroundColor Green
    Add-DhcpServerv4Scope -Name "VLAN 20 - Diseño" -StartRange 192.168.1.50 -EndRange 192.168.1.200 -SubnetMask 255.255.255.0
} else {
    Write-Host "El ámbito DHCP para VLAN 20 - Diseño ya existe" -ForegroundColor Yellow
}

# Configurar opciones de ámbito para VLAN 20
Set-DhcpServerv4OptionValue -ScopeId 192.168.1.0 -Router 192.168.1.1 -DnsDomain $nombreDominio -DnsServer 192.168.3.50

# VLAN 30 (Administración)
if (-not (Test-DhcpScope -ScopeId "192.168.2.0")) {
    Write-Host "Creando ámbito DHCP para VLAN 30 - Administración" -ForegroundColor Green
    Add-DhcpServerv4Scope -Name "VLAN 30 - Administración" -StartRange 192.168.2.50 -EndRange 192.168.2.200 -SubnetMask 255.255.255.0
} else {
    Write-Host "El ámbito DHCP para VLAN 30 - Administración ya existe" -ForegroundColor Yellow
}

# Configurar opciones de ámbito para VLAN 30
Set-DhcpServerv4OptionValue -ScopeId 192.168.2.0 -Router 192.168.2.1 -DnsDomain $nombreDominio -DnsServer 192.168.3.50

# Reiniciar el servicio DHCP para aplicar los cambios
Restart-Service dhcpserver

# ------------------------------------------------------------------------------
# 8. Instalación y configuración del servidor WSUS
# ------------------------------------------------------------------------------

# Instalar el rol de WSUS con la consola de administración
Install-WindowsFeature -Name UpdateServices, UpdateServices-UI -IncludeManagementTools

# Crear el directorio para el contenido de WSUS
$wsusDir = "C:\WSUS"
if (-not (Test-Path -Path $wsusDir)) {
    New-Item -ItemType Directory -Path $wsusDir -Force
}

# Configurar WSUS
& "C:\Program Files\Update Services\Tools\WsusUtil.exe" postinstall CONTENT_DIR=$wsusDir

# Importar el módulo de WSUS
Import-Module UpdateServices

# Configurar WSUS
$wsusServer = Get-WsusServer
$wsusConfig = $wsusServer.GetConfiguration()

# Configurar sincronización
$wsusConfig.SyncFromMicrosoftUpdate = $true
$wsusConfig.Save()

# Configurar idiomas (solo español e inglés)
$wsusConfig.AllUpdateLanguagesEnabled = $false
# Corregir la configuración de idiomas - usar un array de idiomas
$languages = @("en", "es", "sv")
foreach ($language in $languages) {
    $wsusConfig.SetEnabledUpdateLanguages($language)
}
$wsusConfig.Save()

# Configurar clasificaciones de actualizaciones
$wsusSubscription = $wsusServer.GetSubscription()
$wsusSubscription.StartSynchronizationForCategoryOnly()

# Esperar a que finalice la sincronización inicial de categorías
Start-Sleep -Seconds 60

# Habilitar solo actualizaciones críticas y de seguridad
$classifications = @("Critical Updates", "Security Updates")
$wsusClassifications = $wsusServer.GetUpdateClassifications() | Where-Object { $classifications -contains $_.Title.ToString() }
$wsusSubscription.SetUpdateClassifications($wsusClassifications)

# Programar sincronización diaria a las 3:00 AM
$wsusSubscription.SynchronizeAutomatically = $true
$wsusSubscription.SynchronizeAutomaticallyTimeOfDay = (New-TimeSpan -Hours 3)
$wsusSubscription.NumberOfSynchronizationsPerDay = 1
$wsusSubscription.Save()

# Iniciar la primera sincronización
$wsusSubscription.StartSynchronization()

# Crear un grupo de computadoras llamado "Clientes Windows" en WSUS
$wsusGroup = $wsusServer.CreateComputerTargetGroup("Clientes Windows")

# Configurar aprobaciones automáticas para actualizaciones críticas y de seguridad
$rule = $wsusServer.CreateInstallApprovalRule("Aprobación Automática")
$rule.SetUpdateClassifications($wsusClassifications)
$rule.SetComputerTargetGroups(@($wsusGroup))
$rule.Enabled = $true
$rule.Save()

Write-Host "Configuración completada con éxito" -ForegroundColor Green