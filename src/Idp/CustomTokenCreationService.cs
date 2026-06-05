using Duende.IdentityServer.Configuration;
using Duende.IdentityServer.Services;
using Duende.IdentityServer;
using Duende.IdentityServer.Models;
using System.Security.Claims;

namespace Idp;

public class CustomTokenCreationService : DefaultTokenCreationService
{
    public CustomTokenCreationService(TimeProvider timeProvider,
        IKeyMaterialService keys,
        IdentityServerOptions options,
        ILogger<DefaultTokenCreationService> logger)
        : base(timeProvider, keys, options, logger)
    {
    }

    protected override Task<string> CreatePayloadAsync(Token token)
    {
        var clientName = token.ClientId;
        if ((clientName == "mobile-dpop-client") || (clientName == "onboarding-user-client"))
        {
            // get user claims attached to device
            // get user onboarding level
            token.Claims.Add(new Claim("custom1", "custom1Value"));
        }

        return base.CreatePayloadAsync(token);
    }
}
