using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace Idp;

public class PublicKeyService
{
    private static readonly Dictionary<string, (string PublicKey, string Alg)> _inMemoryCache = [];

    public string CreateSession(string publicKey, string alg)
    {
        var authSession = RandomNumberGenerator.GetHexString(32);

        // Add to cache with 10 min lifespan
        // DDoS protection required
        _inMemoryCache.Add(authSession, (publicKey, alg));

        return authSession;
    }

    /// <summary>
    /// Get public key from cache
    /// </summary>
    public string GetPublicKey(string authSession)
    {
        var data = _inMemoryCache.GetValueOrDefault(authSession);
        if (data.PublicKey != null)
        {
            return data.PublicKey;
        }

        throw new ArgumentNullException(nameof(authSession), "something went wrong");
    }

    /// <summary>
    /// Get public key from cache
    /// </summary>
    public SecurityKey GetPublicSecurityKey(string authSession, string alg)
    {
        if (alg == "RS256")
        {
            return GetPublicSecurityKeyRS256(authSession);
        }
        else if (alg == "ES256")
        {
            return GetPublicSecurityKeyES256(authSession);
        }

        throw new ArgumentException("Unsupported algorithm", nameof(alg));
    }

    private SecurityKey GetPublicSecurityKeyRS256(string authSession)
    {
        var publicKeyPem = _inMemoryCache.GetValueOrDefault(authSession);

        if (publicKeyPem.PublicKey != null)
        {
            RsaSecurityKey securityKey;
            var key = RSA.Create();
            key.ImportFromPem(publicKeyPem.PublicKey);
            securityKey = new RsaSecurityKey(key);

            return securityKey;
        }

        throw new ArgumentNullException(nameof(authSession), "something went wrong");
    }

    private SecurityKey GetPublicSecurityKeyES256(string authSession)
    {
        var publicKeyPem = _inMemoryCache.GetValueOrDefault(authSession);

        if (publicKeyPem.PublicKey != null)
        {
            ECDsaSecurityKey securityKey;
            var key = ECDsa.Create();
            key.ImportFromPem(publicKeyPem.PublicKey);
            securityKey = new ECDsaSecurityKey(key);

            return securityKey;
        }

        throw new ArgumentNullException(nameof(authSession), "something went wrong");
    }
}
