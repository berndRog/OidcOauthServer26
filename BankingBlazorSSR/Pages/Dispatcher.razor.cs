using Microsoft.AspNetCore.Components;
namespace BankingBlazorSSR.Pages;

public partial class Dispatcher(
   IHttpContextAccessor httpContextAccessor,
   NavigationManager navigation
) {
   
   protected override void OnInitialized() {
      var http = httpContextAccessor.HttpContext!;
      var user = http.User;

      if (user?.Identity?.IsAuthenticated != true) {
         navigation.NavigateTo("/identity/login?returnUrl=%2Fdispatcher", forceLoad: true);
         return;
      }

      // DEBUG: Log all claims
      var claims = user.Claims.Select(c => $"{c.Type}={c.Value}").ToList();
      Console.WriteLine("=== User Claims ===");
      foreach (var claim in claims) {
         Console.WriteLine(claim);
      }
      Console.WriteLine($"IsInRole(Owner): {user.IsInRole("Owner")}");
      Console.WriteLine($"IsInRole(Employee): {user.IsInRole("Employee")}");

      if (user.IsInRole("Owner")) {
         navigation.NavigateTo("/owner", forceLoad: true);
         return;
      }

      if (user.IsInRole("Employee")) {
         navigation.NavigateTo("/employee", forceLoad: true);
         return;
      }

      navigation.NavigateTo("/no-access", forceLoad: true);
   }
   
}