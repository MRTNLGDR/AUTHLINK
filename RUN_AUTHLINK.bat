@echo off
setlocal
cd /d "%~dp0"

echo ============================================================
echo   AUTHLINK AIIA SUITE - LOCAL DEV RUNTIME
echo ============================================================
echo.

where node >nul 2>nul || (
  echo [ERRO] Node.js 22+ nao encontrado no PATH.
  echo Instale Node.js e execute novamente.
  pause
  exit /b 1
)

where npm >nul 2>nul || (
  echo [ERRO] npm nao encontrado no PATH.
  pause
  exit /b 1
)

where cargo >nul 2>nul || (
  echo [ERRO] Rust/Cargo nao encontrado no PATH.
  echo Instale pelo rustup e execute novamente.
  pause
  exit /b 1
)

where docker >nul 2>nul || (
  echo [ERRO] Docker Desktop nao encontrado no PATH.
  echo Instale/inicie o Docker Desktop e execute novamente.
  pause
  exit /b 1
)

echo [1/3] Instalando dependencias web...
call npm install
if errorlevel 1 goto :fail

echo.
echo [2/3] Preparando Postgres, OpenFGA, Rauthy, modelo e migrations...
node scripts\bootstrap-local.mjs all
if errorlevel 1 goto :fail

echo.
echo [3/3] Iniciando Gateway Rust e interface AuthLink...
node scripts\dev-local.mjs
if errorlevel 1 goto :fail

goto :eof

:fail
echo.
echo [ERRO] O AuthLink nao conseguiu concluir a inicializacao.
echo Veja a mensagem acima. Nenhuma etapa foi marcada como concluida silenciosamente.
pause
exit /b 1
