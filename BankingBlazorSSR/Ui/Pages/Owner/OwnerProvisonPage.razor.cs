using System.Text;
using System.Text.Json;
using BankingBlazorSsr.Api.Clients;
using BankingBlazorSsr.Api.Contracts;
using BankingBlazorSsr.Api.Dtos;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
namespace BankingBlazorSsr.Ui.Pages.Owner;

public partial class OwnerProvisonPage { // dont't use : BasePage here

   [Inject] private IOwnerClient Client { get; set; } = default!;
   [Inject] private AuthenticationStateProvider AuthStateProvider { get; set; } = default!;
   [Inject] private NavigationManager NavigationManager { get; set; } = default!;
   [Inject] private IHttpContextAccessor HttpContextAccessor { get; set; } = default!;
   [Inject] private ILogger<OwnerProvisonPage> Logger { get; set; } = default!;

   // Bind this in the .razor file to display claims
   private string? _idToken;
   private string? _accessToken;
   private List<(string Key, string Value)> _idTokenLines = [];
   private List<(string Key, string Value)> _accessTokenLines = [];
   private List<(string Type, string Value)> _idTokenClaims = [];
   
   private ProvisionDto _provision = default!;

   protected override async Task OnInitializedAsync() {

      // BasePage state
      Loading = true; 
      ErrorMessage = null; 
      Logger.LogInformation("OwnerProvisionPage: OnInitializedAsync");
      
      // Get tokens and decode them to display in the UI for demonstration purposes.
      // In a real application, you might not want to do this.
      var http = HttpContextAccessor.HttpContext!;
      _idToken = await http.GetTokenAsync("id_token");
      _accessToken = await http.GetTokenAsync("access_token");
      _idTokenLines = DecodeJwtToLines(_idToken);
      _accessTokenLines = DecodeJwtToLines(_accessToken);

      // 1) ID-Token Claims auslesen
      var authState = await AuthStateProvider.GetAuthenticationStateAsync();
      var user = authState.User;
      Logger.LogInformation("User Identity: {@Identity}", user?.Identity);
      
      _idTokenClaims = user?.Identity?.IsAuthenticated == true
         ? user.Claims.Select(c => (c.Type, c.Value)).ToList()
         : new List<(string Type, string Value)>();

      Logger.LogInformation("ID Token Claims: {@Claims}", _idTokenClaims);
      
      // 2) Provision
      var resultProvision = await Client.PostProvisionAsync(CancellationToken.None);
      if (resultProvision.IsFailure) {
         HandleError(resultProvision.Error!);
         Loading = false;
         return;
      }
      _provision = resultProvision.Value!;
      
      Loading = false;
   }

   private void ContinueToProfile() {
      // is the profile just provisioned? if so, navigate to profile page
      if (_provision?.ShowProfile ?? false) {
         Logger.LogInformation("Owner just provisioned");
         // profile must be shown to update it, navigate to profile page
         NavigationManager.NavigateTo("/owners/profile");
      }
      else {
         Logger.LogInformation("Owner already provisioned");
         // profile already exists, navigate to home page
         var id = _provision.Id!;
         NavigationManager.NavigateTo($"/owners/{id}");
      }
   }

   private static List<(string Key, string Value)> DecodeJwtToLines(string? jwt) {
      var result = new List<(string, string)>();

      if (string.IsNullOrWhiteSpace(jwt)) {
         result.Add(("token", "(missing)"));
         return result;
      }

      var parts = jwt.Split('.');
      if (parts.Length < 2) {
         result.Add(("token", "invalid"));
         return result;
      }

      var payload = parts[1];
      payload = payload.PadRight(payload.Length + (4 - payload.Length % 4) % 4, '=');
      payload = payload.Replace('-', '+').Replace('_', '/');

      var bytes = Convert.FromBase64String(payload);
      var json = Encoding.UTF8.GetString(bytes);

      using var doc = JsonDocument.Parse(json);

      foreach (var prop in doc.RootElement.EnumerateObject()) {
         result.Add((prop.Name, prop.Value.ToString()));
      }

      return result;
   }

   private static string DecodeJwt(string jwt) {
      var parts = jwt.Split('.');
      if (parts.Length < 2) return "invalid token";

      var payload = parts[1];
      payload = payload.PadRight(payload.Length + (4 - payload.Length % 4) % 4, '=');
      payload = payload.Replace('-', '+').Replace('_', '/');

      var bytes = Convert.FromBase64String(payload);
      return Encoding.UTF8.GetString(bytes);
   }
}