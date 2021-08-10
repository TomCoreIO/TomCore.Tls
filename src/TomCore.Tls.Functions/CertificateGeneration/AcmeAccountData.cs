using System;
using System.ComponentModel.DataAnnotations;

namespace TomCore.Tls.Functions.CertificateGeneration
{
    public class AcmeAccountData
    {
        [Required] public string AcmeAdminEmail { get; init; } = null!;
        [Required] public Uri KeyVaultUri { get; init; } = null!;
    }
}