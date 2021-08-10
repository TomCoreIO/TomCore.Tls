FROM mcr.microsoft.com/dotnet/sdk:5.0

# Install zip
RUN apt-get update && apt-get install zip -y

# Install .NETCore 3.1 and Azure Functions Core Tools 3
WORKDIR /sdk
RUN wget https://packages.microsoft.com/config/debian/10/packages-microsoft-prod.deb -O packages-microsoft-prod.deb &&\
    dpkg -i packages-microsoft-prod.deb &&\
    apt-get update &&\ 
    apt-get install -y apt-transport-https &&\
    apt-get update &&\
    apt-get install -y dotnet-sdk-3.1 &&\
    apt-get install azure-functions-core-tools-3
    
# Install az
RUN curl -sL https://aka.ms/InstallAzureCLIDeb | bash

# Build Function(s)
WORKDIR /build

RUN echo "#!/bin/bash\n" \
         "mkdir /out\n" \
         "cd /src\n" \
         "dotnet publish --output /out --configuration release --no-self-contained\n" \
         "cd /out && zip -r function.zip .\n" \
         "az functionapp deployment source config-zip -g \${RESOURCE_GROUP} -n \${FUNCTION_NAME} --src function.zip --verbose\n" > /build/build.sh
         
RUN chmod +x /build/build.sh

CMD ["/bin/bash", "-c", "/build/build.sh"] 
