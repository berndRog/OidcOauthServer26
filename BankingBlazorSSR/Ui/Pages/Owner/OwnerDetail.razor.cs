using BankingBlazorSsr.Api.Dtos;
using BankingBlazorSsr.Core;
using BankingBlazorSsr.Core.Dto;
using Microsoft.AspNetCore.Components;
namespace BankingBlazorSsr.Ui.Pages.Owner;

public partial class OwnerDetail { // dont use : BasePage here

   [Inject] private IAccountClient AccountClient { get; set; } = default!;
   [Inject] private IOwnerClient OwnerClient { get; set; } = default!;
   [Inject] private NavigationManager navigationManager { get; set; } = default!;
   [Inject] private ILogger<OwnerDetail> logger {get; set; } = default!;
   
   [Parameter] public Guid Id { get; set; }

   private OwnerDto _ownerDto = default!;
   private List<AccountDto> _accountDtos;
   private string? _errorMessage = null;
   
   protected override async Task OnInitializedAsync() {
      logger.LogInformation("OwnerDetail: OnInitializedAsync Id: {1}",Id);

      // BasePage state
      Loading = true; 
      ErrorMessage = null; 
      
      var resultOwner = await OwnerClient.GetById(Id);
      if (resultOwner.IsFailure) {
         HandleError(resultOwner.Error);
         return;
      }
      _ownerDto = resultOwner.Value;
      logger.LogDebug("Loaded owner: {@Owner}", _ownerDto);
      
      
      //var resultAccounts = await accountClient.GetAllByOwner(Id);
      
      
   }

   private void OpenAccount(Guid accountId) {
      var iban = _accountDtos?.FirstOrDefault(a => a.Id == accountId)?.Iban;
      logger.LogInformation("OwnerDetail: nav: /accounts/iban/{1}", iban);
      navigationManager.NavigateTo($"/accounts/iban/{iban}");
   }
   
   private void LeaveForm() {
      navigationManager.NavigateTo("/home");
   }


}