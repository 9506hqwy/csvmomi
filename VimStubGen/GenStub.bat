@ECHO OFF
SET FILENAME=VimService.cs
SET NAMESPACE=VimService
SET OUTPUTDIR=%~dp0..\VimStubSlim

DEL "%OUTPUTDIR%\%FILENAME%"
dotnet-svcutil --outputDir "%OUTPUTDIR%" --noLogo --verbosity Debug --outputFile %FILENAME% --namespace *,%NAMESPACE% --serializer XmlSerializer --wrapped --targetFramework netstandard2.0 %~dp0wsdl\vim25\*.wsdl %~dp0wsdl\vim25\*.xsd
