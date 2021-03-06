## Провайдер аутентификации ЕСИА для ASP.NET Core

### Установка

Установите пакет [AspNetCore.Security.OAuth.Esia](https://www.nuget.org/packages/AspNetCore.Security.OAuth.Esia/)

### Использование

В `Startup.cs` включаем аутентификацию и задаем параметры:
```csharp
services.AddAuthentication().AddEsia(options =>
{
    options.ClientId = "xxxxxxxxx"; // идентификатор системы-клиента, обязателен
    options.ClientCertificate = new X509Certificate2(...); // сертификат системы-клиента, обязателен
    
    // по умолчанию используются боевые адреса ЕСИА, можно поменять на тестовые:
    // options.AuthorizationEndpoint = EsiaConstants.TestAuthorizationUrl;
    // options.TokenEndpoint = EsiaConstants.TestAccessTokenUrl;
    // options.UserInformationEndpoint = EsiaConstants.TestUserInformationUrl;
    
    // получение контактных данных пользователя (почта, телефон), по умолчанию отключено
    // options.FetchContactInfo = true;
});
```
