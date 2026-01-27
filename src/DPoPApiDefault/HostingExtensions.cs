using Duende.AspNetCore.Authentication.JwtBearer.DPoP;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.OpenApi;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.OpenApi;
using NetEscapades.AspNetCore.SecurityHeaders.Infrastructure;
using Serilog;

namespace DPoPApiDefault;

internal static class HostingExtensions
{
    public static WebApplication ConfigureServices(this WebApplicationBuilder builder)
    {
        var services = builder.Services;
        var configuration = builder.Configuration;

        var deploySwaggerUI = builder.Environment.IsDevelopment();

        builder.Services.AddSecurityHeaderPolicies()
        .SetPolicySelector((PolicySelectorContext ctx) =>
        {
            // sum is weak security headers due to Swagger UI deployment
            // should only use in development
            if (deploySwaggerUI)
            {
                // Weakened security headers for Swagger UI
                if (ctx.HttpContext.Request.Path.StartsWithSegments("/swagger"))
                {
                    return SecurityHeadersDefinitionsSwagger.GetHeaderPolicyCollection(builder.Environment.IsDevelopment());
                }

                // Strict security headers
                return SecurityHeadersDefinitionsAPI.GetHeaderPolicyCollection(builder.Environment.IsDevelopment());
            }
            // Strict security headers for production
            else
            {
                return SecurityHeadersDefinitionsAPI.GetHeaderPolicyCollection(builder.Environment.IsDevelopment());
            }
        });

        var stsServer = configuration["StsServer"];

        services.AddAuthentication("dpoptokenscheme")
            .AddJwtBearer("dpoptokenscheme", options =>
            {
                options.Authority = stsServer;
                // TODO add valid aud
                options.TokenValidationParameters.ValidateAudience = false;
                options.MapInboundClaims = false;

                options.TokenValidationParameters.ValidTypes = ["at+jwt"];
            });

        // layers DPoP onto the "token" scheme above
        builder.Services.ConfigureDPoPTokensForScheme("dpoptokenscheme", opt =>
        {
            // Chose a validation mode: either Nonce or IssuedAt. With nonce validation,
            // the api supplies a nonce that must be used to prove that the token was
            // not pre-generated. With IssuedAt validation, the client includes the
            // current time in the proof token, which is compared to the clock. Nonce
            // validation provides protection against some attacks that are possible
            // with IssuedAt validation, at the cost of an additional HTTP request being
            // required each time the API is invoked.
            //
            // See RFC 9449 for more details.
            opt.ValidationMode = ExpirationValidationMode.IssuedAt; // IssuedAt is the default.
        });

        services.AddAuthorizationBuilder()
            .AddPolicy("protectedScope", policy =>
            {
                policy.RequireClaim("scope", "DPoPApiDefaultScope");
            });

        builder.Services.AddOpenApi(options =>
        {
            options.AddDocumentTransformer<BearerSecuritySchemeTransformer>();
        });
        services.AddControllers();

        return builder.Build();
    }

    public static WebApplication ConfigurePipeline(this WebApplication app)
    {
        IdentityModelEventSource.ShowPII = true;
        JsonWebTokenHandler.DefaultInboundClaimTypeMap.Clear();

        app.UseSerilogRequestLogging();

        if (app.Environment.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }

        app.UseSecurityHeaders();

        app.MapOpenApi("/openapi/v1/openapi.json");

        if (app.Environment.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();

            app.UseSwaggerUI(options =>
            {
                options.SwaggerEndpoint("/openapi/v1/openapi.json", "v1");
            }); 
        }

        app.UseRouting();

        app.UseAuthentication();
        app.UseAuthorization();

        app.MapControllers()
            .RequireAuthorization();

        return app;
    }

    internal sealed class BearerSecuritySchemeTransformer(IAuthenticationSchemeProvider authenticationSchemeProvider) : IOpenApiDocumentTransformer
    {
        public async Task TransformAsync(OpenApiDocument document, OpenApiDocumentTransformerContext context, CancellationToken cancellationToken)
        {
            var authenticationSchemes = await authenticationSchemeProvider.GetAllSchemesAsync();
            if (authenticationSchemes.Any(authScheme => authScheme.Name == "Bearer"))
            {
                var requirements = new Dictionary<string, IOpenApiSecurityScheme>
                {
                    ["Bearer"] = new OpenApiSecurityScheme
                    {
                        Type = SecuritySchemeType.Http,
                        Scheme = "bearer", // "bearer" refers to the header name here
                        In = ParameterLocation.Header,
                        BearerFormat = "Json Web Token"
                    }
                };
                document.Components ??= new OpenApiComponents();
                document.Components.SecuritySchemes = requirements;
            }
            document.Info = new()
            {
                Title = "My API Bearer scheme",
                Version = "v1",
                Description = "API for Damien"
            };
        }
    }
}