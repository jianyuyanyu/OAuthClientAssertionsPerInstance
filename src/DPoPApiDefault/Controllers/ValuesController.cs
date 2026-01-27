using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace DPoPApiDefault.Controllers;

[Authorize(Policy = "protectedScope")]
[ApiController]
[Route("api/[controller]")]
public class ValuesController : Controller
{
    [HttpGet]
    [EndpointSummary("This is a summary from OpenApi attributes.")]
    [EndpointDescription("This is a description from OpenApi attributes.")]
    [Produces(typeof(IEnumerable<string>))]
    public IEnumerable<string> Get()
    {
        var authSession = GetAuthSession();
        // debugging info
        var authHeader = Request.Headers.Authorization;
        var claims = User.Claims.Select(c => new { c.Type, c.Value });

        return
        [
            "data 1 from the api protected using OAuth DPoP",
            $"data 2 from the api, auth_session from AT: {authSession}"
        ];
    }

    private string? GetAuthSession()
    {
        var authSessionClaim = User.Claims.FirstOrDefault(c => c.Type == "scope" && c.Value.StartsWith("auth_session"));
        var authSession = authSessionClaim?.Value.Replace("auth_session:", "");
        return authSession;
    }
}
