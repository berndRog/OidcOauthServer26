using BankingBlazorSsr.Api.Dtos;
using BankingBlazorSsr.Core.Dto;
namespace BankingBlazorSsr.Core;

public interface IOwnerClient {
    Task<Result<IEnumerable<OwnerDto>?>> GetAll();
    Task<Result<OwnerDto?>> GetById(Guid ownerId);
    Task<Result<OwnerDto?>> GetByUserName(string userName);
    Task<Result<IEnumerable<OwnerDto>?>> GetByName(string name);
    //Task<Result<OwnerDto?>> GetByUserId(string userId);
    //Task<Result<OwnerDto?>> Post(OwnerDto ownerDto);
    //Task<Result<OwnerDto?>> Put(OwnerDto ownerDto);
    
    Task<bool> ExistsByUserName(string userName);
}