@echo off
if [%1]==[] goto usage
if [%2]==[] goto usage
docker build . -t functions_builder
docker run -e RESOURCE_GROUP=%1 -e FUNCTION_NAME=%2 --rm --mount type=bind,source=%HOMEDRIVE%%HOMEPATH%/.azure,target=/root/.azure --mount type=bind,source=%CD%,target=/src functions_builder
echo Done
goto :eof
:usage
echo "BuildAndDeploy [Name of ResourceGroup] [Name of Function App to deploy to]"