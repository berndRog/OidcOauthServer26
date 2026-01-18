using Microsoft.AspNetCore.Identity;
using static OidcOauthServer.Data.AdminRights;
namespace OidcOauthServer.Data;

/// <summary>
/// Seeds demo users for the course.
/// - customer@demo.local
/// - admin@demo.local (employee with AdminRights bitmask)
///
/// This is course/demo-only.
/// </summary>
public sealed class SeedUsersHostedService : IHostedService {
   private readonly IServiceProvider _sp;

   public SeedUsersHostedService(IServiceProvider sp) => _sp = sp;

   public async Task StartAsync(CancellationToken ct) {
      using var scope = _sp.CreateScope();
      var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();

      // ----------------------------
      // Customer demo user
      // ----------------------------
      await EnsureUserAsync(
         users,
         email: "customer@demo.local",
         password: "Customer#1234",
         accountType: "customer",
         customerId: Guid.Parse("00000000-0000-0000-0000-000000000101"),
         employeeId: null,
         adminRights: null
      );

      // ----------------------------
      // Admin demo user (Employee)
      // Example rights: manage cars + bookings + customers + employees
      // ----------------------------
      var rights =
         (int)(ManageCars | ManageBookings | ManageCustomers | ManageEmployees);
      await EnsureUserAsync(
         users,
         email: "bernd@mail.local",
         password: "Geh1m_",
         accountType: "employee",
         customerId: null,
         employeeId: Guid.Parse("00000000-0000-0000-0000-000000000201"),
         adminRights: rights
      );
   }

   private static async Task EnsureUserAsync(
      UserManager<ApplicationUser> users,
      string email,
      string password,
      string accountType,
      Guid? customerId,
      Guid? employeeId,
      int? adminRights
   ) {
      var existing = await users.FindByEmailAsync(email);
      if (existing is not null) return;

      var user = new ApplicationUser {
         UserName = email,
         Email = email,
         EmailConfirmed = true,

         AccountType = accountType,
         CustomerId = customerId,
         EmployeeId = employeeId,
         AdminRights = adminRights
      };

      var result = await users.CreateAsync(user, password);
      if (!result.Succeeded) {
         var errors = string.Join("; ", result.Errors.Select(e => $"{e.Code}:{e.Description}"));
         throw new InvalidOperationException($"Failed to seed user '{email}': {errors}");
      }
   }

   public Task StopAsync(CancellationToken ct) => Task.CompletedTask;
}

/*
DE:
- Seedet zwei Demo-User, damit Login sofort getestet werden kann.
- AdminRights werden als int Bitmaske gespeichert und später als Claim ausgegeben.
*/