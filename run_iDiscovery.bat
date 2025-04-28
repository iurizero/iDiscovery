@echo off
title iDiscovery - Network Scanner
color 0A

:: Verifica se está rodando como administrador
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Executando com privilegios de administrador...
    powershell -Command "Start-Process -Verb RunAs -FilePath '%~dp0%~nx0'"
    exit /b
)

:: Navega para a pasta do script
cd /d "%~dp0"

:: Executa o programa
python iDiscovery.py

:: Mantém o terminal aberto
echo.
echo Escaneamento concluido!
echo Pressione qualquer tecla para fechar o programa...
pause >nul 