using System;
using System.ComponentModel.DataAnnotations;

namespace TomCore.Tls.Functions.CertificateGeneration
{
    // ReSharper disable once ClassNeverInstantiated.Global
    public class CertificateOrderInfo
    {
        [Required] public string DomainName { get; init; } = null!;
        [Required] public string SubscriptionId { get; init; } = null!;
        [Required] public string ResourceGroupName { get; init; } = null!;
        [Required] public string ZoneName { get; init; } = null!;
        [Required] public Uri KeyVaultUri { get; init; } = null!;
    }
}