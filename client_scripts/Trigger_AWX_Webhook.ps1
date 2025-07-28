# Nombre del script: Trigger_AWX_Webhook.ps1
# Descripción: Verifica la conectividad de red corporativa y envía el webhook a AWX.
# Ejecutado por una tarea programada.

# --- CONFIGURACIÓN ---
# Estos valores serán inyectados por Configurar_Ansible_Cliente.ps1
$AWX_WEBHOOK_URL = "http://172.25.21.254:31712/api/v2/job_templates/11/github/"
$AWX_WEBHOOK_TOKEN = "w8oTtasnTJpaTTi0T3WB1LbI5mz20XMmBH7dn4MimSvs7y9YYM"
$TempPasswordFile = "C:\Windows\Temp\ansible_admin_pass.txt"
$StatusFilePath = "C:\ProgramData\Ansible\ProvisioningStatus.json"
$DomainControllerFQDN = "dc01.lafabril.com.ec" # FQDN de un controlador de dominio para verificar conectividad
$ScheduledTaskName = "Ansible_Provisioning_Trigger" # Nombre de la tarea programada

# --- Función para actualizar el estado de la UI ---
function Update-ProvisioningStatus {
    param (
        [string]$CurrentStep,
        [string]$Detail,
        [int]$Progress,
        [string]$OverallStatus,
        [string]$StepKey,
        [string]$StepStatus
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
        Write-Warning "No se pudo actualizar el archivo de estado de la UI desde Trigger_AWX_Webhook: $($_.Exception.Message)"
    }
}

Write-Host "$(Get-Date) - Trigger_AWX_Webhook.ps1 iniciado."

Update-ProvisioningStatus -CurrentStep "Esperando conexión a red corporativa..." -Detail "Verificando conectividad al dominio." -Progress 30 -OverallStatus "in_progress" -StepKey "waiting_for_network" -StepStatus "in_progress"

# --- Verificar Conectividad de Red Corporativa ---
$isConnectedToDomain = $false
try {
    # Opción 1: Verificar si el equipo está unido a un dominio (más fiable para entornos de dominio)
    # Si el equipo ya está unido al dominio, es una señal fuerte de conectividad corporativa.
    $ComputerInfo = Get-ComputerInfo -Property CsDomain
    if ($ComputerInfo.CsDomain -ne "WORKGROUP" -and $ComputerInfo.CsDomain -ne $null) {
        Write-Host "$(Get-Date) - Equipo detectado como unido a un dominio: $($ComputerInfo.CsDomain)"
        $isConnectedToDomain = $true
    }
    # Opción 2: Intentar hacer ping a un controlador de dominio (si no está unido aún o para verificación adicional)
    if (-not $isConnectedToDomain) {
        if (Test-Connection -ComputerName $DomainControllerFQDN -Count 1 -Quiet) {
            Write-Host "$(Get-Date) - Conectividad a controlador de dominio ($DomainControllerFQDN) verificada."
            $isConnectedToDomain = $true
        } else {
            Write-Host "$(Get-Date) - No se pudo conectar a $DomainControllerFQDN. La tarea se reintentará más tarde."
        }
    }
} catch {
    Write-Warning "$(Get-Date) - Error al verificar conectividad: $($_.Exception.Message)"
}

if (-not $isConnectedToDomain) {
    Write-Host "$(Get-Date) - No hay conexión a la red corporativa. Saliendo. La tarea programada se reintentará."
    exit 0 # Salir sin error, la tarea programada se reintentará
}

Write-Host "$(Get-Date) - Conexión a red corporativa detectada. Procediendo a notificar a AWX."

Update-ProvisioningStatus -CurrentStep "Conexión a red corporativa establecida." -Detail "Notificando a AWX para iniciar el aprovisionamiento." -Progress 40 -OverallStatus "in_progress" -StepKey "waiting_for_network" -StepStatus "completed"
Update-ProvisioningStatus -CurrentStep "Notificando a AWX..." -Detail "Enviando datos del equipo." -Progress 45 -OverallStatus "in_progress" -StepKey "connect_to_awx" -StepStatus "in_progress"

# --- Leer la contraseña generada ---
$WinRMPassword = ""
if (Test-Path $TempPasswordFile) {
    $WinRMPassword = Get-Content -Path $TempPasswordFile -Encoding ASCII | Out-String | Select-Object -First 1
    $WinRMPassword = $WinRMPassword.Trim()
    Write-Host "$(Get-Date) - Contraseña de AnsibleAdmin leída del archivo temporal."
} else {
    Write-Error "$(Get-Date) - Archivo de contraseña temporal no encontrado. No se puede enviar el webhook."
    Update-ProvisioningStatus -CurrentStep "Error en activación online" -Detail "Fallo al leer contraseña." -Progress 45 -OverallStatus "failed" -StepKey "connect_to_awx" -StepStatus "failed"
    exit 1
}

# --- Enviar Webhook a AWX ---
try {
    $ComputerName = $env:COMPUTERNAME
    $IPAddress = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -like "Ethernet*" -or $_.InterfaceAlias -like "Wi-Fi*"}).IPAddress | Select-Object -First 1
    $SerialNumber = (Get-WmiObject Win32_Bios).SerialNumber

    $Headers = @{
        "Content-Type" = "application/json"
        "X-Ansible-Webhook-Secret" = $AWX_WEBHOOK_TOKEN
    }

    $Body = @{
        "host_name" = $ComputerName
        "ip_address" = $IPAddress
        "serial_number" = $SerialNumber
        "ansible_admin_password" = $WinRMPassword # Pasar la contraseña generada a AWX
        "extra_vars" = @{
            "new_machine_name" = $ComputerName
            "new_machine_ip" = $IPAddress
            "new_machine_serial" = $SerialNumber
            "ansible_admin_password_generated" = $WinRMPassword
        }
    } | ConvertTo-Json

    Invoke-RestMethod -Uri $AWX_WEBHOOK_URL -Method Post -Headers $Headers -Body $Body -ErrorAction Stop
    Write-Host "$(Get-Date) - Webhook enviado a AWX exitosamente. AWX iniciará el aprovisionamiento." -ForegroundColor Green
    Update-ProvisioningStatus -CurrentStep "Webhook enviado a AWX." -Detail "Aprovisionamiento en curso." -Progress 50 -OverallStatus "in_progress" -StepKey "connect_to_awx" -StepStatus "completed"

    # Deshabilitar/Eliminar la tarea programada después de un envío exitoso
    try {
        Unregister-ScheduledTask -TaskName "$ScheduledTaskName" -Confirm:$false
        Write-Host "$(Get-Date) - Tarea programada '$ScheduledTaskName' deshabilitada/eliminada."
    } catch {
        Write-Warning "$(Get-Date) - No se pudo deshabilitar/eliminar la tarea programada '$ScheduledTaskName': $($_.Exception.Message)"
    }

} catch {
    Write-Error "$(Get-Date) - Error al enviar el webhook a AWX. El aprovisionamiento automático puede no iniciarse. Mensaje: $($_.Exception.Message)"
    Update-ProvisioningStatus -CurrentStep "Error en activación online" -Detail "Fallo al enviar webhook a AWX." -Progress 45 -OverallStatus "failed" -StepKey "connect_to_awx" -StepStatus "failed"
    exit 1
}
