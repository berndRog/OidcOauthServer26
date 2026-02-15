using BankingBlazorSsr.Api.Errors;
using BankingBlazorSsr.Core;
using Microsoft.AspNetCore.Components;

namespace BankingBlazorSsr.Ui.Common;

public abstract class BasePage : ComponentBase {
   
   // Common base page for all pages, providing error handling and navigation.
   [Inject] protected NavigationManager Nav { get; set; } = default!;
   [Inject] protected ILogger<BasePage> BaseLogger { get; set; } = default!;

   protected string? ErrorMessage;
   protected bool Loading = true;

   protected void HandleError(ApiError error) {
      BaseLogger.LogWarning("API Error {Status}: {Title}", error.Status, error.Title);

      switch (error.Status) {
         case 401:
            Nav.NavigateTo("/identity/login", true);
            return;

         case 403:
            Nav.NavigateTo("/forbidden");
            return;

         case 404:
            Nav.NavigateTo("/notfound");
            return;

         case 409:
         case 422:
            ErrorMessage = error.Detail ?? error.Title;
            break;

         default:
            ErrorMessage = "Server not reachable.";
            break;
      }

      Loading = false;
      StateHasChanged();
   }
}