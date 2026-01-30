# Use the official ASP.NET Core SDK image for building
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src

# Copy csproj and restore as distinct layers
COPY ["ICDLAdminPortal.csproj", "./"]
RUN dotnet restore "ICDLAdminPortal.csproj"

# Copy everything else and build
COPY . .
RUN dotnet publish "ICDLAdminPortal.csproj" -c Release -o /app/publish

# Build runtime image
FROM mcr.microsoft.com/dotnet/aspnet:9.0
WORKDIR /app
COPY --from=build /app/publish .

# Expose port 8080 (default for most cloud providers)
ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080

# Define entry point
ENTRYPOINT ["dotnet", "ICDLAdminPortal.dll"]
