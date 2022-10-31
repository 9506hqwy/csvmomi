@ECHO OFF
SET FILENAME=StsService.cs
SET NAMESPACE=StsService
SET OUTPUTDIR=%~dp0..\StsService

DEL "%OUTPUTDIR%\%FILENAME%"
dotnet-svcutil --outputDir "%OUTPUTDIR%" --noLogo --verbosity Debug --outputFile %FILENAME% --namespace *,%NAMESPACE% --serializer XmlSerializer --wrapped --targetFramework netstandard2.0 %~dp0wsdl\*.wsdl %~dp0wsdl\*.xsd
