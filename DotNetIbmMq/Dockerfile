FROM mcr.microsoft.com/dotnet/runtime:8.0 AS base
WORKDIR /app

ARG CERT_ROOTCA_SRC=vcc-root-ca-g2.pem
ARG CERT_ROOTCA_DEST=vcc-root-ca-g2.crt
ARG CERT_SUBCA_SRC=vcc-subca-06-g3.pem
ARG CERT_SUBCA_DEST=vcc-subca-06-g3.crt

RUN echo "CERT_ROOTCA_SRC=${CERT_ROOTCA_SRC}" && \
    echo "CERT_ROOTCA_DEST=${CERT_ROOTCA_DEST}" && \
    echo "CERT_SUBCA_SRC=${CERT_SUBCA_SRC}" && \
    echo "CERT_SUBCA_DEST=${CERT_SUBCA_DEST}"

COPY ./cert/${CERT_ROOTCA_SRC} /usr/local/share/ca-certificates/${CERT_ROOTCA_DEST}
COPY ./cert/${CERT_SUBCA_SRC} /usr/local/share/ca-certificates/${CERT_SUBCA_DEST}
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