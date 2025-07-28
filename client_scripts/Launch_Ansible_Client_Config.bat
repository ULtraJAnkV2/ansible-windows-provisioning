@echo off
setlocal

:: Nombres de los scripts
set "PS_UI_SCRIPT_NAME=Display_Provisioning_UI.ps1"
set "PS_CONFIG_SCRIPT_NAME=Configurar_Ansible_Cliente.ps1"
set "STATUS_FILE_NAME=ProvisioningStatus.json"

:: Rutas completas (asumiendo que los .bat, .ps1 y .json están en el mismo directorio)
set "PS_UI_SCRIPT_PATH=%~dp0%PS_UI_SCRIPT_NAME%"
set "PS_CONFIG_SCRIPT_PATH=%~dp0%PS_CONFIG_SCRIPT_NAME%"
set "STATUS_FILE_PATH=C:\ProgramData\Ansible\%STATUS_FILE_NAME%"

:: Crear el directorio de datos de Ansible si no existe
IF NOT EXIST "C:\ProgramData\Ansible" (
    ECHO Creando directorio C:\ProgramData\Ansible...
    mkdir "C:\ProgramData\Ansible"
)

:: Crear o inicializar el archivo de estado JSON
:: ¡IMPORTANTE! Este JSON debe coincidir con la estructura inicial esperada por Display_Provisioning_UI.ps1
IF NOT EXIST "%STATUS_FILE_PATH%" (
    ECHO {"current_step": "Iniciando...", "detail": "", "progress": 0, "status": "in_progress", "step_details": {"winrm_config": "pending", "ansible_admin_user": "pending", "waiting_for_network": "pending", "connect_to_awx": "pending", "install_base_apps": "pending", "rename_and_join_da": "pending", "install_sap_gui": "pending", "configure_office": "pending", "finished": "pending"}, "last_update": "%DATE% %TIME%"} > "%STATUS_FILE_PATH%"
    ECHO Archivo de estado JSON inicializado.
)

:: Comprobar si se está ejecutando como administrador
NET SESSION >NUL 2>&1
IF %ERRORLEVEL% NEQ 0 (
    ECHO Solicitando privilegios de administrador...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    EXIT /B
) ELSE (
    ECHO Ejecutando como administrador.
)

:: --- INICIAR LA INTERFAZ DE USUARIO EN SEGUNDO PLANO ---
ECHO Iniciando interfaz de usuario de aprovisionamiento...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS_UI_SCRIPT_PATH%" -WindowStyle Hidden &

:: --- EJECUTAR EL SCRIPT DE CONFIGURACIÓN PRINCIPAL ---
ECHO.
ECHO Ejecutando el script de configuracion principal: %PS_CONFIG_SCRIPT_NAME%
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS_CONFIG_SCRIPT_PATH%"

ECHO.
ECHO Proceso de configuracion del cliente completado.
:: La ventana de UI se cerrará automáticamente después de un tiempo o al hacer clic en "Finalizado" / "Error - Cerrar"
pause
endlocal
