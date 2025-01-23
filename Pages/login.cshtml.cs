using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Web;

namespace OAuthLogin.Pages
{
    public class LoginModel : PageModel
    {
        private readonly IConfiguration _configuration;

        public LoginModel(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public IActionResult OnPostSignIn(string provider)
        {
            if (string.IsNullOrEmpty(provider))
                return BadRequest("Provider is required");

            var authConfig = _configuration.GetSection("Authentication");
            string authorizationEndpoint;
            string clientId;

            switch (provider)
            {
                case "Google":
                    authorizationEndpoint = authConfig["Google:AuthorizationEndpoint"];
                    clientId = authConfig["Google:ClientId"];
                    break;
                case "Facebook":
                    authorizationEndpoint = authConfig["Facebook:AuthorizationEndpoint"];
                    clientId = authConfig["Facebook:ClientId"];
                    break;
                default:
                    return BadRequest("Unsupported provider");
            }

            // Construct the redirect URL
            var redirectUri = Url.Page("/Index", null, null, Request.Scheme);
            var queryParams = new Dictionary<string, string>
            {
                { "client_id", clientId },
                { "redirect_uri", redirectUri },
                { "response_type", "code" },
                { "scope", provider == "Google" ? "openid email profile" : "email,public_profile" },
                { "state", provider }
            };

            var authUrl = authorizationEndpoint + "?" + string.Join("&",
                queryParams.Select(kvp => $"{HttpUtility.UrlEncode(kvp.Key)}={HttpUtility.UrlEncode(kvp.Value)}"));

            return Redirect(authUrl);
        }
    }
}
