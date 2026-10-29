@echo off
chcp 65001 >nul
title foxkit 脚本版
cd /d %~dp0

rem ===== 浏览器在不在 =====
if not exist "Surf\Firefox\firefox.exe" (
  echo [还差一步] Surf\Firefox 里没有 firefox.exe。
  echo 请把装好的 Firefox 程序文件夹里的文件复制到 Surf\Firefox，或用程序版的「准备浏览器」。
  pause
  exit /b 1
)

rem ===== PowerShell 执行策略探活（不绕过策略；不行就问用户要不要一次性放行）=====
powershell -NoProfile -File "%~dp0mkconfig.ps1" -Probe >nul 2>&1
if errorlevel 1 (
  echo 你的电脑还没允许运行 PowerShell 脚本，mkconfig.ps1 跑不起来。
  echo 解决办法：把「当前用户」的脚本策略设为 RemoteSigned，只需做一次，之后不再问。
  choice /c YN /m "现在就设置吗"
  if errorlevel 2 (
    echo 好，不设置就先到这里。设置好以后再双击本文件。
    pause
    exit /b 1
  )
  powershell -NoProfile -Command "Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force"
  echo 已设置。再跑一次探活……
  powershell -NoProfile -File "%~dp0mkconfig.ps1" -Probe >nul 2>&1
  if errorlevel 1 (
    echo 还是不行，可能被公司/学校策略锁住了。这种情况请用程序版。
    pause
    exit /b 1
  )
)

rem ===== 校验并列出节点 =====
powershell -NoProfile -File "%~dp0mkconfig.ps1" -List
if errorlevel 1 (
  echo node.txt 里没有可用节点，请检查后重试。
  pause
  exit /b 1
)
set /p COUNT=<Surf\valid-count.txt
set PICK=1
if %COUNT% GTR 1 (
  set /p PICK=输入要用的节点序号（直接回车 = 第 1 条）：
  if "%PICK%"=="" set PICK=1
)

rem ===== 生成配置 =====
powershell -NoProfile -File "%~dp0mkconfig.ps1" -Pick %PICK%
set RC=%errorlevel%
if %RC%==4 (
  pause
  exit /b 1
)
if %RC%==2 (
  pause
  exit /b 1
)
if %RC%==3 (
  pause
  exit /b 1
)

rem ===== 启动 =====
if %RC%==0 (
  echo 正在启动 sing-box 内核（会开一个控制台窗口，关掉它就断网）……
  start "sing-box 内核（关掉这个窗口就断网）" "%~dp0Surf\core\sing-box.exe" run -c "%~dp0Surf\config.json"
  timeout /t 2 /nobreak >nul
)
echo 正在打开专用浏览器……
start "" "%~dp0Surf\Firefox\firefox.exe" -profile "%~dp0Surf\ff-data" -no-remote
echo 已启动。这个窗口可以关掉。
timeout /t 3 /nobreak >nul
exit /b 0
