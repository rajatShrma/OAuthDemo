using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace OAuthLogin.Pages;

[Authorize]
public class DashboardModel : PageModel
{
    private readonly ILogger<DashboardModel> _logger;

    public DashboardModel(ILogger<DashboardModel> logger)
    {
        _logger = logger;
    }

    public void OnGet()
    {
    }
}

