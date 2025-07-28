# Nombre del script: Configurar_Ansible_Cliente.ps1 (Versión 6 - Offline Setup & Scheduled Task)
# Descripción: Configura un equipo Windows para la conexión WinRM de Ansible,
# crea un usuario local con contraseña aleatoria y programa una tarea
# para notificar a AWX cuando el equipo se conecte a la red corporativa.
#
# ¡IMPORTANTE! Ejecuta este script con permisos de ADMINISTRADOR.

# --- CONFIGURACIÓN ---
$AnsibleServerIP = "172.25.21.254" # IP de tu servidor Ansible (AWX)
$WinRMUser = "AnsibleAdmin"
$WinRMListenerPort = 5986 # Puerto WinRM HTTPS (5985 es HTTP)

# --- CONFIGURACIÓN DE AWX WEBHOOK ---
# ¡REEMPLAZA ESTOS VALORES CON LOS DE TU PLANTILLA DE TRABAJO EN AWX!
$AWX_WEBHOOK_URL = "https://tu_awx_url/api/v2/job_templates/ID_DE_TU_PLANTILLA/webhook/" # <--- ¡ACTUALIZAR ESTO!
$AWX_WEBHOOK_TOKEN = "TuTokenSecretoDeWebhook" # <--- ¡ACTUALIZAR ESTO!

# --- CONFIGURACIÓN DE LA TAREA PROGRAMADA ---
$ScheduledTaskName = "Ansible_Provisioning_Trigger"
$TriggerScriptPath = "C:\ProgramData\Ansible\Trigger_AWX_Webhook.ps1" # Nuevo script que se ejecutará al activarse
$DomainControllerFQDN = "dc01.lafabril.com.ec" # FQDN de un controlador de dominio para verificar conectividad

# --- GENERAR CONTRASEÑA SEGURA ALEATORIA ---
$WinRMPassword = ([char[]]([char]'!'..[char]'~') | Where-Object { $_ -notin '`', '"', "'", '\', '/', '[', ']', ':', ';', '<', '>', ',', '.', '?', '|', '=', '+', '{', '}', '~', '(', ')' } | Get-Random -Count 16) -join ''
Write-Host "Contraseña generada para '$WinRMUser': (Se registrará en un archivo temporal seguro)" -ForegroundColor Yellow

# --- Ruta para almacenar la contraseña temporalmente (¡SEGURIDAD!) ---
# Este archivo será leído por Trigger_AWX_Webhook.ps1 y luego eliminado por el playbook de Ansible.
$TempPasswordFile = "C:\Windows\Temp\ansible_admin_pass.txt"
$StatusFilePath = "C:\ProgramData\Ansible\ProvisioningStatus.json" # Ruta del archivo de estado de la UI

Write-Host "Iniciando configuración OFFLINE del cliente para Ansible..." -ForegroundColor Green

# --- 0. Inicializar el archivo de estado de la UI (si no existe) ---
if (-not (Test-Path $StatusFilePath)) {
    # Asegurarse de que el directorio exista
    if (-not (Test-Path (Split-Path $StatusFilePath))) {
        New-Item -ItemType Directory -Path (Split-Path $StatusFilePath) -Force | Out-Null
    }
    # Inicializar el JSON
    @{
        current_step = "Iniciando configuración offline..."
        detail = "Preparando equipo para conexión con Ansible al detectar red corporativa."
        progress = 5
        status = "in_progress"
        step_details = @{
            winrm_config = "pending"
            ansible_admin_user = "pending"
            waiting_for_network = "pending" # Nuevo estado
            connect_to_awx = "pending"
            install_base_apps = "pending"
            rename_and_join_da = "pending"
            install_sap_gui = "pending"
            configure_office = "pending"
            finished = "pending"
        }
        last_update = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    } | ConvertTo-Json -Compress | Set-Content -Path $StatusFilePath -Encoding UTF8
    Write-Host "Archivo de estado de UI inicializado." -ForegroundColor Green
}

# --- Función para actualizar el estado de la UI ---
function Update-ProvisioningStatus {
    param (
        [string]$CurrentStep,
        [string]$Detail,
        [int]$Progress,
        [string]$OverallStatus,
        [string]$StepKey, # Clave del paso en step_details (ej. "winrm_config")
        [string]$StepStatus # "pending", "in_progress", "completed", "failed"
    )
    try {
        $statusData = Get-Content -Path $StatusFilePath -Raw -Encoding UTF8 | ConvertFrom-Json
        $statusData.current_step = $CurrentStep
        $statusData.detail = $Detail
        $statusData.progress = $Progress
        $statusData.status = $OverallStatus
        $statusData.step_details.$StepKey = $StepStatus
        $statusData.last_update = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        $statusData | ConvertTo-Json -Compress | Set-Content -Path $StatusFilePath -Encoding UTF8
    } catch {
        Write-Warning "No se pudo actualizar el archivo de estado de la UI: $($_.Exception.Message)"
    }
}

Update-ProvisioningStatus -CurrentStep "Iniciando configuración offline..." -Detail "Preparando WinRM y usuario local." -Progress 10 -OverallStatus "in_progress" -StepKey "winrm_config" -StepStatus "in_progress"

# --- 1. Activar y Configurar WinRM ---
Write-Host "1. Configurando el servicio WinRM..." -ForegroundColor Yellow
Enable-PSRemoting -Force -SkipNetworkProfileCheck # Habilita WinRM y sus reglas de firewall por defecto

Update-ProvisioningStatus -CurrentStep "Configurando WinRM..." -Detail "Creando certificado HTTPS y listener." -Progress 15 -OverallStatus "in_progress" -StepKey "winrm_config" -StepStatus "in_progress"

# --- 2. Crear o Usar Certificado Auto-Firmado para WinRM HTTPS ---
Write-Host "2. Creando o verificando certificado auto-firmado para WinRM HTTPS..." -ForegroundColor Yellow
try {
    $cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like "CN=$env:COMPUTERNAME" } | Select-Object -First 1
    if (-not $cert) {
        $cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation Cert:\LocalMachine\My -Type SSLServerAuthentication
        Write-Host "Certificado auto-firmado creado exitosamente." -ForegroundColor Green
    } else {
        Write-Host "Se encontró un certificado auto-firmado existente." -ForegroundColor Cyan
    }
}
catch {
    Write-Error "Fallo al crear o encontrar el certificado. Mensaje: $($_.Exception.Message)"
    Update-ProvisioningStatus -CurrentStep "Error en configuración offline" -Detail "Fallo de certificado WinRM." -Progress 15 -OverallStatus "failed" -StepKey "winrm_config" -StepStatus "failed"
    exit 1
}

# --- 3. Configurar Listener WinRM HTTPS ---
Write-Host "3. Configurando listener WinRM HTTPS en el puerto $WinRMListenerPort..." -ForegroundColor Yellow
try {
    Get-WSManInstance -ResourceURI winrm/config/Listener | Where-Object { $_.Port -eq 5985 -or $_.Port -eq $WinRMListenerPort } | ForEach-Object {
        Write-Host "Eliminando listener existente en el puerto $($_.Port) y transporte $($_.Transport)..." -ForegroundColor Cyan
        Remove-WSManInstance -ResourceURI winrm/config/Listener -SelectorSet @{Address='*'; Port=$_.Port; Transport=$_.Transport}
    }
}
catch {
    Write-Warning "No se pudieron eliminar listeners WinRM existentes: $($_.Exception.Message)"
}

try {
    New-WSManInstance -ResourceURI winrm/config/Listener -SelectorSet @{Address="*"; Port=$WinRMListenerPort; Transport="HTTPS"} -ValueSet @{Hostname=$env:COMPUTERNAME; CertificateThumbprint=$cert.Thumbprint}
    Write-Host "Listener WinRM HTTPS creado exitosamente en el puerto $WinRMListenerPort." -ForegroundColor Green
}
catch {
    Write-Warning "Fallo al crear el listener WinRM HTTPS (puede que ya exista o haya un problema): $($_.Exception.Message)"
    try {
        Set-WSManInstance -ResourceURI winrm/config/Listener -SelectorSet @{Address="*";Port=$WinRMListenerPort;Transport="HTTPS"} -ValueSet @{Hostname=$env:COMPUTERNAME;CertificateThumbprint=$cert.Thumbprint}
        Write-Host "Listener WinRM HTTPS actualizado exitosamente en el puerto $WinRMListenerPort." -ForegroundColor Green
    }
    catch {
        Write-Error "Fallo irrecuperable al crear o actualizar el listener WinRM HTTPS: $($_.Exception.Message)"
        Update-ProvisioningStatus -CurrentStep "Error en configuración offline" -Detail "Fallo de listener WinRM." -Progress 15 -OverallStatus "failed" -StepKey "winrm_config" -StepStatus "failed"
        exit 1
    }
}

# --- 4. Desactivar el Firewall de Windows (¡ADVERTENCIA DE SEGURIDAD!) ---
# ¡PARA PRODUCCIÓN, QUITA ESTO Y SOLO ABRE LOS PUERTOS 5985/5986!
Write-Host "4. Desactivando el Firewall de Windows (¡ADVERTENCIA: Riesgo de seguridad!)..." -ForegroundColor Red
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled False

Update-ProvisioningStatus -CurrentStep "Configurando usuario AnsibleAdmin..." -Detail "Creando usuario local y permisos." -Progress 20 -OverallStatus "in_progress" -StepKey "ansible_admin_user" -StepStatus "in_progress"

# --- 5. Crear o Verificar Usuario Local AnsibleAdmin y añadirlo a Administradores ---
Write-Host "5. Creando o verificando usuario local '$WinRMUser' y añadiéndolo a Administradores..." -ForegroundColor Yellow
try {
    $securePassword = ConvertTo-SecureString -String $WinRMPassword -AsPlainText -Force
    
    if (Get-LocalUser -Name $WinRMUser -ErrorAction SilentlyContinue) {
        Write-Host "El usuario '$WinRMUser' ya existe. Verificando membresía en el grupo Administradores." -ForegroundColor Cyan
        Add-LocalGroupMember -Group "Administradores" -Member $WinRMUser -ErrorAction SilentlyContinue | Out-Null
        Write-Host "Usuario '$WinRMUser' verificado y asegurado en el grupo Administradores." -ForegroundColor Green
    } else {
        New-LocalUser -Name $WinRMUser -Password $securePassword -Description "Usuario para la conexión Ansible WinRM" -ErrorAction Stop
        Write-Host "Usuario '$WinRMUser' creado." -ForegroundColor Green
        
        Add-LocalGroupMember -Group "Administradores" -Member $WinRMUser -ErrorAction Stop
        Write-Host "Usuario '$WinRMUser' añadido al grupo Administradores." -ForegroundColor Green
    }
    # Almacenar la contraseña generada en un archivo temporal para que Trigger_AWX_Webhook.ps1 la lea.
    # ¡ADVERTENCIA DE SEGURIDAD! Este archivo debe ser eliminado por el playbook de Ansible.
    $WinRMPassword | Out-File -FilePath $TempPasswordFile -Encoding ASCII -Force
    Write-Host "Contraseña de '$WinRMUser' guardada temporalmente en $TempPasswordFile." -ForegroundColor Yellow

}
catch {
    Write-Error "Fallo crítico al crear/modificar el usuario '$WinRMUser' o añadirlo a Administradores: $($_.Exception.Message)"
    Update-ProvisioningStatus -CurrentStep "Error en configuración offline" -Detail "Fallo de usuario AnsibleAdmin." -Progress 20 -OverallStatus "failed" -StepKey "ansible_admin_user" -StepStatus "failed"
    exit 1
}

# --- 6. Configurar Modo de Autenticación de WinRM ---
Write-Host "6. Configurando el modo de autenticación de WinRM (Basic y CredSSP)..." -ForegroundColor Yellow
try {
    Set-Item WSMan:\localhost\Service\Auth\Basic -Value $true -Force
    Write-Host "Autenticación Basic habilitada para WinRM." -ForegroundColor Green

    Set-Item WSMan:\localhost\Service\Auth\CredSSP -Value $true -Force
    Write-Host "Autenticación CredSSP habilitada en el servicio WinRM." -ForegroundColor Green
    
    Set-Item WSMan:\localhost\Client\Auth\CredSSP -Value $true -Force
    Write-Host "Autenticación CredSSP habilitada en el cliente WinRM." -ForegroundColor Green
}
catch {
    Write-Error "Fallo al configurar la autenticación WinRM: $($_.Exception.Message)"
    Update-ProvisioningStatus -CurrentStep "Error en configuración offline" -Detail "Fallo de autenticación WinRM." -Progress 20 -OverallStatus "failed" -StepKey "winrm_config" -StepStatus "failed"
    exit 1
}


# --- 7. Configurar TrustedHosts de WinRM ---
Write-Host "7. Configurando TrustedHosts de WinRM para $AnsibleServerIP..." -ForegroundColor Yellow
$currentTrustedHosts = (Get-Item WSMan:\localhost\Client\TrustedHosts).Value
if ($currentTrustedHosts -notlike "*$AnsibleServerIP*") {
    if (-not [string]::IsNullOrEmpty($currentTrustedHosts)) {
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value "$currentTrustedHosts,$AnsibleServerIP" -Force
    } else {
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value "$AnsibleServerIP" -Force
    }
    Write-Host "El servidor Ansible ($AnsibleServerIP) ha sido añadido a TrustedHosts." -ForegroundColor Green
} else {
    Write-Host "El servidor Ansible ($AnsibleServerIP) ya está en TrustedHosts." -ForegroundColor Cyan
}

Update-ProvisioningStatus -CurrentStep "Configuración offline completada." -Detail "Programando activación online." -Progress 25 -OverallStatus "in_progress" -StepKey "winrm_config" -StepStatus "completed"

# --- 8. Crear el script Trigger_AWX_Webhook.ps1 ---
Write-Host "8. Creando script de activación para AWX..." -ForegroundColor Yellow
$TriggerScriptContent = @"
# Nombre del script: Trigger_AWX_Webhook.ps1
# Descripción: Verifica la conectividad de red corporativa y envía el webhook a AWX.
# Ejecutado por una tarea programada.

# --- CONFIGURACIÓN ---
`$AWX_WEBHOOK_URL = "$AWX_WEBHOOK_URL"
`$AWX_WEBHOOK_TOKEN = "$AWX_WEBHOOK_TOKEN"
`$TempPasswordFile = "$TempPasswordFile"
`$StatusFilePath = "$StatusFilePath"
`$DomainControllerFQDN = "$DomainControllerFQDN" # FQDN de un controlador de dominio para verificar conectividad
`$ScheduledTaskName = "$ScheduledTaskName" # Nombre de la tarea programada

# --- Función para actualizar el estado de la UI ---
function Update-ProvisioningStatus {
    param (
        [string]`$CurrentStep,
        [string]`$Detail,
        [int]`$Progress,
        [string]`$OverallStatus,
        [string]`$StepKey,
        [string]`$StepStatus
    )
    try {
        `$statusData = Get-Content -Path `$StatusFilePath -Raw -Encoding UTF8 | ConvertFrom-Json
        `$statusData.current_step = `$CurrentStep
        `$statusData.detail = `$Detail
        `$statusData.progress = `$Progress
        `$statusData.status = `$OverallStatus
        `$statusData.step_details.`$StepKey = `$StepStatus
        `$statusData.last_update = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        `$statusData | ConvertTo-Json -Compress | Set-Content -Path `$StatusFilePath -Encoding UTF8
    } catch {
        Write-Warning "No se pudo actualizar el archivo de estado de la UI desde Trigger_AWX_Webhook: `$(_.Exception.Message)"
    }
}

Write-Host "$(Get-Date) - Trigger_AWX_Webhook.ps1 iniciado."

Update-ProvisioningStatus -CurrentStep "Esperando conexión a red corporativa..." -Detail "Verificando conectividad al dominio." -Progress 30 -OverallStatus "in_progress" -StepKey "waiting_for_network" -StepStatus "in_progress"

# --- Verificar Conectividad de Red Corporativa ---
`$isConnectedToDomain = `$false
try {
    # Opción 1: Verificar si el equipo está unido a un dominio (más fiable para entornos de dominio)
    `$ComputerInfo = Get-ComputerInfo -Property CsDomain
    if (`$ComputerInfo.CsDomain -ne "WORKGROUP" -and `$ComputerInfo.CsDomain -ne `$null) {
        Write-Host "$(Get-Date) - Equipo detectado como unido a un dominio: `$($ComputerInfo.CsDomain)"
        `$isConnectedToDomain = `$true
    }
    # Opción 2: Intentar hacer ping a un controlador de dominio (si no está unido aún o para verificación adicional)
    if (-not `$isConnectedToDomain) {
        if (Test-Connection -ComputerName `$DomainControllerFQDN -Count 1 -Quiet) {
            Write-Host "$(Get-Date) - Conectividad a controlador de dominio (`$DomainControllerFQDN) verificada."
            `$isConnectedToDomain = `$true
        } else {
            Write-Host "$(Get-Date) - No se pudo conectar a `$DomainControllerFQDN. Reintentando en el próximo ciclo."
        }
    }
} catch {
    Write-Warning "$(Get-Date) - Error al verificar conectividad: `$(_.Exception.Message)"
}

if (-not `$isConnectedToDomain) {
    Write-Host "$(Get-Date) - No hay conexión a la red corporativa. Saliendo. La tarea programada se reintentará."
    exit 0 # Salir sin error, la tarea programada se reintentará
}

Write-Host "$(Get-Date) - Conexión a red corporativa detectada. Procediendo a notificar a AWX."

Update-ProvisioningStatus -CurrentStep "Conexión a red corporativa establecida." -Detail "Notificando a AWX para iniciar el aprovisionamiento." -Progress 40 -OverallStatus "in_progress" -StepKey "waiting_for_network" -StepStatus "completed"
Update-ProvisioningStatus -CurrentStep "Notificando a AWX..." -Detail "Enviando datos del equipo." -Progress 45 -OverallStatus "in_progress" -StepKey "connect_to_awx" -StepStatus "in_progress"

# --- Leer la contraseña generada ---
`$WinRMPassword = ""
if (Test-Path `$TempPasswordFile) {
    `$WinRMPassword = Get-Content -Path `$TempPasswordFile -Encoding ASCII | Out-String | Select-Object -First 1
    `$WinRMPassword = `$WinRMPassword.Trim()
    Write-Host "$(Get-Date) - Contraseña de AnsibleAdmin leída del archivo temporal."
} else {
    Write-Error "$(Get-Date) - Archivo de contraseña temporal no encontrado. No se puede enviar el webhook."
    Update-ProvisioningStatus -CurrentStep "Error en activación online" -Detail "Fallo al leer contraseña." -Progress 45 -OverallStatus "failed" -StepKey "connect_to_awx" -StepStatus "failed"
    exit 1
}

# --- Enviar Webhook a AWX ---
try {
    `$ComputerName = `$env:COMPUTERNAME
    `$IPAddress = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -like "Ethernet*" -or `$_.InterfaceAlias -like "Wi-Fi*"}).IPAddress | Select-Object -First 1
    `$SerialNumber = (Get-WmiObject Win32_Bios).SerialNumber

    `$Headers = @{
        "Content-Type" = "application/json"
        "X-Ansible-Webhook-Secret" = `$AWX_WEBHOOK_TOKEN
    }

    `$Body = @{
        "host_name" = `$ComputerName
        "ip_address" = `$IPAddress
        "serial_number" = `$SerialNumber
        "ansible_admin_password" = `$WinRMPassword # Pasar la contraseña generada a AWX
        "extra_vars" = @{
            "new_machine_name" = `$ComputerName
            "new_machine_ip" = `$IPAddress
            "new_machine_serial" = `$SerialNumber
            "ansible_admin_password_generated" = `$WinRMPassword
        }
    } | ConvertTo-Json

    Invoke-RestMethod -Uri `$AWX_WEBHOOK_URL -Method Post -Headers `$Headers -Body `$Body -ErrorAction Stop
    Write-Host "$(Get-Date) - Webhook enviado a AWX exitosamente. AWX iniciará el aprovisionamiento." -ForegroundColor Green
    Update-ProvisioningStatus -CurrentStep "Webhook enviado a AWX." -Detail "Aprovisionamiento en curso." -Progress 50 -OverallStatus "in_progress" -StepKey "connect_to_awx" -StepStatus "completed"

    # Deshabilitar/Eliminar la tarea programada después de un envío exitoso
    try {
        Unregister-ScheduledTask -TaskName "`$ScheduledTaskName" -Confirm:`$false
        Write-Host "$(Get-Date) - Tarea programada '`$ScheduledTaskName' deshabilitada/eliminada."
    } catch {
        Write-Warning "$(Get-Date) - No se pudo deshabilitar/eliminar la tarea programada '`$ScheduledTaskName': `$(_.Exception.Message)"
    }

} catch {
    Write-Error "$(Get-Date) - Error al enviar el webhook a AWX. El aprovisionamiento automático puede no iniciarse. Mensaje: `$(_.Exception.Message)"
    Update-ProvisioningStatus -CurrentStep "Error en activación online" -Detail "Fallo al enviar webhook a AWX." -Progress 45 -OverallStatus "failed" -StepKey "connect_to_awx" -StepStatus "failed"
    exit 1
}
"@

    $TriggerScriptContent | Out-File -FilePath $TriggerScriptPath -Encoding UTF8 -Force
    Write-Host "Script de activación '$TriggerScriptPath' creado exitosamente." -ForegroundColor Green

    # --- 9. Programar Tarea en Windows ---
    Write-Host "9. Programando tarea en Windows para activar AWX al conectar a la red..." -ForegroundColor Yellow
    try {
        # Definir la acción: ejecutar el script de activación
        $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$TriggerScriptPath`""

        # Definir el disparador: al conectar a CUALQUIER red o al unirse al dominio
        $Trigger1 = New-ScheduledTaskTrigger -AtStartup
        $Trigger1.Delay = "PT1M" # Retraso de 1 minuto después del inicio para dar tiempo a la red
        $Trigger1.RepetitionInterval = "PT5M" # Reintentar cada 5 minutos
        $Trigger1.RepetitionDuration = "PT1H" # Durante 1 hora (reintentará por 1 hora si no hay conexión)

        # Definir la configuración de la tarea
        $Settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartOnDemand -DontStopIfGoingOnBatteries -RunResultMEssageOnly -ExecutionTimeLimit "PT1H"
        $Settings.MultipleInstances = "IgnoreNew" # Ignorar nuevas instancias si una ya está corriendo

        # Definir el principal (cuenta bajo la cual se ejecuta la tarea)
        # SYSTEM es ideal para tareas de inicio de sistema/red
        $Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

        # Crear la tarea programada
        Register-ScheduledTask -TaskName $ScheduledTaskName -Action $Action -Trigger $Trigger1 -Settings $Settings -Principal $Principal -Description "Activa el aprovisionamiento de Ansible al conectar a la red corporativa." -Force
        Write-Host "Tarea programada '$ScheduledTaskName' creada exitosamente." -ForegroundColor Green

    } catch {
        Write-Error "Fallo crítico al programar la tarea '$ScheduledTaskName': $($_.Exception.Message)"
        Update-ProvisioningStatus -CurrentStep "Error en configuración offline" -Detail "Fallo al programar tarea." -Progress 25 -OverallStatus "failed" -StepKey "waiting_for_network" -StepStatus "failed"
        exit 1
    }

    Update-ProvisioningStatus -CurrentStep "Configuración offline completada." -Detail "El equipo se activará al conectar a la red corporativa." -Progress 25 -OverallStatus "in_progress" -StepKey "waiting_for_network" -StepStatus "in_progress" # Estado final de esta fase

    Write-Host "Proceso de configuración OFFLINE completado. El equipo está en standby." -ForegroundColor Green
    Write-Host "Cuando el equipo se conecte a la red corporativa, la tarea programada '$ScheduledTaskName' se activará." -ForegroundColor Yellow
    