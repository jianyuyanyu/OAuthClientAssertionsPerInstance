using Duende.AccessTokenManagement;
using Duende.AccessTokenManagement.DPoP;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using Serilog;
using Serilog.Sinks.SystemConsole.Themes;
using System;
using System.Security.Cryptography;
using System.Text.Json;

namespace ConsolePerInstanceAssertion;

public class Program
{
    public static void Main(string[] args)
    {
        Console.Title = "DPoP client with client assertions";

        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Debug()
            .WriteTo.Console(theme: AnsiConsoleTheme.Code)
            .CreateLogger();

        CreateHostBuilder(args).Build().Run();
    }

    public static IHostBuilder CreateHostBuilder(string[] args)
    {
        var host = Host.CreateDefaultBuilder(args)
            .UseSerilog()

            .ConfigureServices((services) =>
            {
                services.AddDistributedMemoryCache();

                var keySessionService = new KeySessionService();
                var session = keySessionService.CreateGetSessionAsync().GetAwaiter().GetResult();

                services.AddSingleton<KeySessionService>(t => keySessionService);
                services.AddScoped<IClientAssertionService, ClientAssertionService>();
                // https://docs.duendesoftware.com/foss/accesstokenmanagement/advanced/client_assertions/


                services.AddClientCredentialsTokenManagement()
                    .AddClient("mobile-dpop-client", client =>
                    {
                        client.TokenEndpoint = new Uri("https://localhost:5101/connect/token");

                        client.ClientId = ClientId.Parse("mobile-dpop-client");
                        // Using client assertion
                        //client.ClientSecret = "905e4892-7610-44cb-a122-6209b38c882f";

                        client.Scope = Scope.Parse($"DPoPApiDefaultScope auth_session:{session.AuthSession}");
                        client.DPoPJsonWebKey = CreateDPoPKey();
                    })
                    .AddClient("onboarding-user-client", client =>
                    {
                        client.TokenEndpoint =  new Uri("https://localhost:5101/connect/token");

                        client.ClientId = ClientId.Parse("onboarding-user-client");
                        // Using client assertion
                        //client.ClientSecret = "905e4892-7610-44cb-a122-6209b38c882f";

                        client.Scope = Scope.Parse($"OnboardingUserScope auth_session:{session.AuthSession}");
                        client.DPoPJsonWebKey = CreateDPoPKey();
                    });

                services.AddClientCredentialsHttpClient("mobile-dpop-client", ClientCredentialsClientName.Parse("mobile-dpop-client"), client =>
                {
                    client.BaseAddress = new Uri("https://localhost:5105/");
                });
                services.AddClientCredentialsHttpClient("onboarding-user-client", ClientCredentialsClientName.Parse("onboarding-user-client"), client =>
                {
                    client.BaseAddress = new Uri("https://localhost:5101/");
                });

                services.AddHostedService<DPoPClient>();
            });

        return host;
    }

    private static DPoPProofKey CreateDPoPKey()
    {
        var key = new RsaSecurityKey(RSA.Create(2048));
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(key);
        jwk.Alg = "PS256";
        var jwkJson = JsonSerializer.Serialize(jwk);
        return DPoPProofKey.Parse(jwkJson);
    }
}