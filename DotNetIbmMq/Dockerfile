FROM mcr.microsoft.com/dotnet/runtime:8.0 AS base
WORKDIR /app

ARG CERTIFICATES_SUBCA_SRC=vcc-subca-06-g3.pem
ARG CERTIFICATES_ROOTCA_SRC=vcc-root-ca-g2.pem
ARG CERTIFICATES_SUBCA_DEST=vcc-subca-06-g3.crt
ARG CERTIFICATES_ROOTCA_DEST=vcc-root-ca-g2.crt

RUN echo "CERTIFICATES_SUBCA_SRC=${CERTIFICATES_SUBCA_SRC}" && \
    echo "CERTIFICATES_ROOTCA_SRC=${CERTIFICATES_ROOTCA_SRC}" && \
    echo "CERTIFICATES_SUBCA_DEST=${CERTIFICATES_SUBCA_DEST}" && \
    echo "CERTIFICATES_ROOTCA_DEST=${CERTIFICATES_ROOTCA_DEST}"

COPY ./cert/${CERTIFICATES_SUBCA_SRC} /usr/local/share/ca-certificates/${CERTIFICATES_SUBCA_DEST}
COPY ./cert/${CERTIFICATES_ROOTCA_SRC} /usr/local/share/ca-certificates/${CERTIFICATES_ROOTCA_DEST}
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