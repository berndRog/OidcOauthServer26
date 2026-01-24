namespace WebClientMvc.Models.Dtos;

public sealed record CustomerProfileDto(
   string Email,
   string FirstName,
   string LastName,
   string? Street,
   string? PostalCode,
   string? City,
   string? Country
);
