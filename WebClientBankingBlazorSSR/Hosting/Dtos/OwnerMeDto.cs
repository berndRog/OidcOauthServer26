namespace WebClientBankingBlazorSSR.Hosting.Dtos;

public sealed record OwnerMeDto(
   Guid Id,
   string Email,
   string Subject,
   string Status
);
