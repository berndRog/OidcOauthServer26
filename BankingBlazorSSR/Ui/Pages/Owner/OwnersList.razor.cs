using BankingBlazorSsr.Api.Contracts;
using BankingBlazorSsr.Api.Dtos;
using BankingBlazorSsr.Ui.Common;
using Microsoft.AspNetCore.Components;
namespace BankingBlazorSsr.Ui.Pages.Owner;

public partial class OwnersList: BasePage {

   [Inject] private IOwnerClient ownerClient { get; set; } = default!;
   [Inject] private NavigationManager navigationManager { get; set; } = default!;
   [Inject] private ILogger<OwnerDetail> logger { get; set; } = default!;
   
   private List<OwnerDto> _ownerDtos = [];

   protected override async Task OnInitializedAsync() {
      
      var result = await ownerClient.GetAllAsync();
      if (result.IsFailure) {
         HandleError(result.Error);
         return;
      }
      _ownerDtos = result.Value?
         .OrderBy(o => o.Lastname)
         .ThenBy(o => o.Firstname)
         .ToList();

   }
    
 
   private void OpenOwner(Guid ownerId) {
      logger.LogInformation("OwnerList: nav: /owners/{1}", ownerId);
      navigationManager.NavigateTo($"/owners/{ownerId}");
   }
}