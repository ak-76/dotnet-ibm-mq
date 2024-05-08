FROM mcr.microsoft.com/dotnet/runtime:8.0 AS base
WORKDIR /app
ADD ./cert/vcc-subca-06-g3.crt /usr/local/share/ca-certificates/vcc-subca-06-g3.crt
ADD ./cert/vcc-root-ca-g2.crt /usr/local/share/ca-certificates/vcc-root-ca-g2.crt
RUN update-ca-certificates


FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src
COPY ["DotNetIbmMq/DotNetIbmMq.csproj", "DotNetIbmMq/"]
RUN dotnet restore "./DotNetIbmMq/DotNetIbmMq.csproj"
COPY . .
WORKDIR "/src/DotNetIbmMq"
RUN dotnet build "./DotNetIbmMq.csproj" -c $BUILD_CONFIGURATION -o /app/build

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "./DotNetIbmMq.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
RUN mkdir -p /app/cert
RUN chmod -R 755 /app/cert
RUN mkdir -p /var/log/xmstrace
RUN chmod -R 777 /var/log/xmstrace
RUN ls -la /app/cert
ENTRYPOINT ["dotnet", "DotNetIbmMq.dll"]