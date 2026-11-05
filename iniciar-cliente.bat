@echo off
setlocal

cd /d "%~dp0"

if not exist "runtime\bin\java.exe" (
    echo ERRO: runtime\bin\java.exe nao foi encontrado.
    echo Copie uma JDK completa para a pasta runtime.
    pause
    exit /b 1
)

if not exist "runtime\bin\keytool.exe" (
    echo ERRO: runtime\bin\keytool.exe nao foi encontrado.
    echo O runtime deve ser uma JDK completa.
    pause
    exit /b 1
)

if not exist "lib\javafx-sdk-17.0.21\lib" (
    echo ERRO: JavaFX nao foi encontrado em lib\javafx-sdk-17.0.21\lib.
    pause
    exit /b 1
)

if not exist "bin\client\gui\Main.class" (
    echo ERRO: A versao atual compilada da app nao foi encontrada em bin.
    echo Compile a GUI com: make gui
    pause
    exit /b 1
)

runtime\bin\java.exe ^
  --module-path "lib\javafx-sdk-17.0.21\lib" ^
  --add-modules javafx.controls,javafx.fxml ^
  -Djava.library.path="lib\javafx-sdk-17.0.21\bin" ^
  -cp "bin" client.gui.Main

if errorlevel 1 (
    echo.
    echo O cliente terminou com um erro.
)

pause
