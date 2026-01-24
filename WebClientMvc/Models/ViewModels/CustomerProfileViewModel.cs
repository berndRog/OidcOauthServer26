namespace WebClientMvc.Models.ViewModels;

public sealed class CustomerProfileVm {
   public string Email { get; set; } = "";
   public string FirstName { get; set; } = "";
   public string LastName { get; set; } = "";
   public string? Street { get; set; }
   public string? PostalCode { get; set; }
   public string? City { get; set; }
   public string? Country { get; set; }
}