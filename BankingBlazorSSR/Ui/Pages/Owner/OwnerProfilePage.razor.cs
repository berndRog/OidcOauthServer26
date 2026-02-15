using BankingBlazorSsr.Api.Clients;
using BankingBlazorSsr.Api.Dtos;
using BankingBlazorSsr.Ui.Common;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Forms;

namespace BankingBlazorSsr.Ui.Pages.Owner;

/// <summary>
/// Owner profile edit page.
/// Demonstrates form state handling, validation lifecycle,
/// navigation semantics (Back vs Cancel), and API error handling.
/// </summary>
public partial class OwnerProfilePage {

   // ---- Dependency Injection ------------------------------------------------
   [Inject] private OwnerClient OwnerClient { get; set; } = default!;
   [Inject] private NavigationManager Navigation { get; set; } = default!;
   [Inject] private ILogger<OwnerProfilePage> Logger { get; set; } = default!;
   // ---- Navigation Context --------------------------------------------------
   // Optional return URL (passed via query string)
   // After Save or Leave navigation returns here instead of fixed route
   [Parameter, SupplyParameterFromQuery]
   public string? Return { get; set; }
   // ---- UI State ------------------------------------------------------------
   private bool _saving;
   private bool _showGlobalErrors;
   private string? _saveError;
   private string? _saveOk;
   // ---- Form Model ----------------------------------------------------------
   // Current editable model
   private OwnerDto _ownerDto = new();
   // Snapshot of original state (used for Cancel)
   private OwnerDto _originalOwnerDto = new();
   // Blazor form state manager
   private EditContext _editContext = default!;

   // -------------------------------------------------------------------------
   // Initialization
   // -------------------------------------------------------------------------
   protected override async Task OnInitializedAsync() {

      Loading = true;
      ErrorMessage = null;

      // Create initial EditContext so form can render immediately
      RebuildEditContext();

      // Load profile from API (Result pattern)
      var result = await OwnerClient.GetProfileAsync();
      if (result.IsFailure) {
         HandleError(result.Error!);
         Loading = false;
         return;
      }

      _ownerDto = result.Value ?? new OwnerDto();

      // Store snapshot for Cancel
      _originalOwnerDto = Clone(_ownerDto);

      Logger.LogDebug("Loaded owner profile: {@Profile}", _ownerDto);

      // Recreate EditContext because model instance changed
      RebuildEditContext();
      Loading = false;
   }


   // -------------------------------------------------------------------------
   // Form Lifecycle
   // -------------------------------------------------------------------------
   /// <summary>
   /// Recreates EditContext when model instance changes.
   /// Important: Validation state belongs to EditContext, not the model.
   /// </summary>
   private void RebuildEditContext() {
      if (_editContext != null)
         _editContext.OnValidationStateChanged -= ValidationChanged;

      _editContext = new EditContext(_ownerDto);
      _editContext.OnValidationStateChanged += ValidationChanged;
   }

   private void ValidationChanged(object? sender, ValidationStateChangedEventArgs e) {
      _showGlobalErrors = _editContext.GetValidationMessages().Any();
   }
   
   // -------------------------------------------------------------------------
   // Navigation semantics
   // -------------------------------------------------------------------------
   /// <summary>
   /// Cancel = discard changes and stay in application context.
   /// No persistence operation.
   /// </summary>
   private void Cancel() {
      _ownerDto = Clone(_originalOwnerDto);
      RebuildEditContext();
      _saveError = null;
      _saveOk = null;
   }

   /// <summary>
   /// Leave = navigate away from page.
   /// Uses return URL if available.
   /// </summary>
   private void GoBack() => Navigation.NavigateTo(Return ?? "/owners");


   // -------------------------------------------------------------------------
   // Save operation
   // -------------------------------------------------------------------------
   /// <summary>
   /// Validates form, sends update to API and handles domain/API errors.
   /// </summary>
   private async Task SaveAsync() {
      _saving = true;
      _saveError = null;
      _saveOk = null;

      // Prevent API call if invalid
      if (!_editContext.Validate()) {
         _showGlobalErrors = true;
         _saving = false;
         return;
      }

      Logger.LogDebug("Update owner profile: {@Profile}", _ownerDto);

      var result = await OwnerClient.UpdateProfileAsync(_ownerDto);

      if (result.IsFailure) {

         var err = result.Error!;
         Logger.LogWarning("Save failed {Status}: {Title}", err.Status, err.Title);

         // Business validation errors stay on page
         if (err.Status is 409 or 422) {
            _saveError = err.Detail ?? err.Title;
            _saving = false;
            return;
         }

         // Authentication / authorization / not found handled globally
         HandleError(err);
         _saving = false;
         return;
      }

      // Success: API returned updated entity
      _ownerDto = result.Value ?? _ownerDto;
      RebuildEditContext();

      _saveOk = "Saved.";
      _saving = false;

      // After successful save navigate to detail view
      Navigation.NavigateTo($"/owners/{_ownerDto.Id}");
   }


   // -------------------------------------------------------------------------
   // Helper
   // -------------------------------------------------------------------------
   /// <summary>
   /// DTO clone used to restore form state after Cancel.
   /// DTO cloning is acceptable because DTOs are data containers,
   /// not domain entities.
   /// </summary>
   private static OwnerDto Clone(OwnerDto src) => new() {
      Id = src.Id,
      Firstname = src.Firstname,
      Lastname = src.Lastname,
      Email = src.Email,
      Street = src.Street,
      PostalCode = src.PostalCode,
      City = src.City,
      Country = src.Country
   };
}
