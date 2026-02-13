using System.ComponentModel.DataAnnotations;
namespace BankingBlazorSsr.Api.Dtos;

using System.ComponentModel.DataAnnotations;

public sealed record EmployeeDto {

   [Required]
   [StringLength(100, MinimumLength = 2,
      ErrorMessage = "First name must be between 2 and 80 characters.")]
   public string Firstname { get; set; } = string.Empty;

   [Required]
   [StringLength(100, MinimumLength = 2,
      ErrorMessage = "Last name must be between 2 and 80 characters.")]
   public string Lastname { get; set; } = string.Empty;
   
   [StringLength(100, MinimumLength = 2,
      ErrorMessage = "Company name must be less then 80 characters.")]
   public string? CompanyName { get; set; }
   
   [Required]
   [EmailAddress(ErrorMessage = "Please enter a valid email address.")]
   [StringLength(254)] // RFC 5321 practical limit
   public string Email { get; set; } = string.Empty;


}
