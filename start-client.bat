@echo off
setlocal

cd /d "%~dp0"

if not exist "runtime\bin\java.exe" (
    echo ERROR: runtime\bin\java.exe was not found.
    echo Copy a complete JDK into the runtime folder.
    pause
    exit /b 1
)

if not exist "runtime\bin\keytool.exe" (
    echo ERROR: runtime\bin\keytool.exe was not found.
    echo The runtime must be a complete JDK.
    pause
    exit /b 1
)

if not exist "lib\javafx-sdk-17.0.21\lib" (
    echo ERROR: JavaFX was not found in lib\javafx-sdk-17.0.21\lib.
    pause
    exit /b 1
)

if not exist "bin\client\gui\Main.class" (
    echo ERROR: The current compiled application was not found in bin.
    echo Compile the GUI with: make gui
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
    echo The client terminated with an error.
)

pause
