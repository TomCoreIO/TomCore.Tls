using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace TomCore.Tls.Functions.CertificateGeneration
{
    public static class ConfigurationReader
    {
                public static CertificateOrderInfo[] GetCertificateOrderInfosConfiguration(ILogger logger)
                {
                    var options = new JsonSerializerOptions
                    {
                        PropertyNameCaseInsensitive = true,
                        AllowTrailingCommas = true,
                    };
                    const string dnsChallengesConfigurationKey = "DnsChallenges";
                    var dnsChallengesAsString = Environment.GetEnvironmentVariable(dnsChallengesConfigurationKey);
                    if (String.IsNullOrEmpty(dnsChallengesAsString))
                    {
                        throw new ArgumentException($"Configuration key '{dnsChallengesConfigurationKey}' is missing or empty");
                    }
                    var dnsChallenges = JsonSerializer.Deserialize<CertificateOrderInfo[]>(dnsChallengesAsString, options) ?? Array.Empty<CertificateOrderInfo>();
                    ValidateLogErrorsAndThrow(dnsChallenges, dnsChallengesConfigurationKey, logger);
                    return dnsChallenges;
                }
        
                public static AcmeAccountData GetAcmeAccountDataConfiguration(ILogger logger)
                {
                    const string acmeAdminEmailConfigurationKey = "AcmeAdminEmail";
                    const string acmeAccountKeyVaultUriConfigurationKey = "AcmeAccountKeyVaultUri";
                    var acmeAccountData = new AcmeAccountData
                    {
                        AcmeAdminEmail = Environment.GetEnvironmentVariable(acmeAdminEmailConfigurationKey) ?? throw new ArgumentException($"Configuration key '{acmeAdminEmailConfigurationKey}' is missing or empty"),
                        KeyVaultUri = new Uri(Environment.GetEnvironmentVariable(acmeAccountKeyVaultUriConfigurationKey) ?? throw new ArgumentException($"Configuration key '{acmeAccountKeyVaultUriConfigurationKey}' is missing or empty"))
                    };
        
                    ValidateLogErrorsAndThrow(acmeAccountData, "Acme Account Data", logger);
                    return acmeAccountData;
                }
        
                static void ValidateLogErrorsAndThrow<T>(T obj, string name, ILogger logger)
                {
                    var results = new List<ValidationResult>();
                    var success = Validator.TryValidateObject(obj!, new ValidationContext(obj!), results, true);
                    if (!success)
                    {
                        logger.LogError("{Name} validation failed", name);
                        LogValidationErrors(results, logger);
                        throw new ArgumentException(name);
                    }
                }
        
                static void LogValidationErrors(IEnumerable<ValidationResult> validationResults, ILogger logger)
                {
                    foreach (var validationResult in validationResults)
                    {
                        logger.LogError("{ErrorMessage}", validationResult.ErrorMessage);
                    }
                }
    }
}