using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Security.Claims;
using System.Text.Json;

namespace OAuthLogin.Pages;

public class IndexModel : PageModel
{
    private readonly IConfiguration _configuration;

    public Dictionary<string, string> UserInfo { get; private set; }

    public IndexModel(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    public async Task<IActionResult> OnGetAsync(string code, string state)
    {
        if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(state))
            return BadRequest("Invalid callback response");

        var authConfig = _configuration.GetSection("Authentication");
        string tokenEndpoint = string.Empty;
        string userInfoEndpoint = string.Empty;
        string clientId = string.Empty;
        string clientSecret = string.Empty;

        switch (state)
        {
            case "Google":
                tokenEndpoint = authConfig["Google:TokenEndpoint"];
                userInfoEndpoint = authConfig["Google:UserInfoEndpoint"];
                clientId = authConfig["Google:ClientId"];
                clientSecret = authConfig["Google:ClientSecret"];
                break;

            case "Facebook":
                tokenEndpoint = authConfig["Facebook:TokenEndpoint"];
                userInfoEndpoint = authConfig["Facebook:UserInfoEndpoint"];
                clientId = authConfig["Facebook:ClientId"];
                clientSecret = authConfig["Facebook:ClientSecret"];
                break;

            default:
                return BadRequest("Unsupported provider");
        }

        using var client = new HttpClient();

        // Exchange the code for an access token
        var tokenResponse = await client.PostAsync(tokenEndpoint, new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("client_id", clientId),
            new KeyValuePair<string, string>("client_secret", clientSecret),
            new KeyValuePair<string, string>("code", code),
            new KeyValuePair<string, string>("redirect_uri", Url.Page("/index", null, null, Request.Scheme)),
            new KeyValuePair<string, string>("grant_type", "authorization_code")
        }));
        if (!tokenResponse.IsSuccessStatusCode)
            return BadRequest("Token exchange failed");

        var tokenData = JsonDocument.Parse(await tokenResponse.Content.ReadAsStringAsync()).RootElement;
        var accessToken = tokenData.GetProperty("access_token").GetString();

        // Use the access token to fetch user info
        client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
        var userInfoResponse = await client.GetAsync(userInfoEndpoint);
        if (!userInfoResponse.IsSuccessStatusCode)
            return BadRequest("Failed to fetch user info");

        var userInfoJson = JsonDocument.Parse(await userInfoResponse.Content.ReadAsStringAsync()).RootElement;
        UserInfo = userInfoJson.EnumerateObject().ToDictionary(prop => prop.Name, prop => prop.Value.ToString());

        // Set the authenticated user
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, UserInfo["name"]),
            new Claim(ClaimTypes.Email, UserInfo["email"])
        };

        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

        // Redirect to the desired page
        return RedirectToPage("/Dashboard"); // Ensures redirection to the correct page
    }
}
