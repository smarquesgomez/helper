@echo off
echo Instalando dependencias...
pip install flask pyinstaller

echo.
echo Generando ejecutable...
pyinstaller --onefile --noconsole ^
  --add-data "templates;templates" ^
  --add-data "static;static" ^
  --add-data "analyzers;analyzers" ^
  --add-data "core;core" ^
  --name "IFXAnalyzer" ^
  main.py

echo.
echo Listo! El ejecutable esta en: dist\IFXAnalyzer.exe
pause
