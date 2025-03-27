using MA_CFGscratchpad.Analysis;
using Microsoft.Extensions.Logging;

namespace MA_CFGscratchpad;

class Program
{
    private static void Main(string[] _)
    {
        const string code =
            """
            // Represents a simple GET endpoint with an auth check
            class Main
            {
                AuthService authService = new AuthService();
                SecretService secretService = new SecretService();
                
                public void GetSecretEndpoint()
                {
                    //authService.authCheck<SecretEntity>();
                    var secret = secretService.GetSecret();
                    return secret;
                }
            }

            // Represents some kind of auth check to look out for in the sec analysis
            class AuthService
            {
                public void authCheck<T>() {}
            }

            // Represents arbitrary middle layers between endpoint and DB access
            class SecretService
            {
                DatabaseService databaseService = new DatabaseService();
                
                public string GetSecret()
                {
                    return databaseService.GetSecret().Secret;
                }
            }

            // Represents the usual "await context.Secrets.FirstOrDefaultAsync(...)" access
            class DatabaseService
            {
                public SecretEntity GetSecret() {
                    return new SecretEntity("13374cc355");
                }
            }

            class SecretEntity
            {
                public string Secret;
                
                public SecretEntity(string secret)
                {
                    this.Secret = secret;
                }
            }
            """;

        var loggerFactory = LoggerFactory.Create(
            builder => builder
                .AddConsole()
                .AddFilter("MA_CFGscratchpad", LogLevel.Debug)
        );
        var analysisService = new AnalysisService(
            loggerFactory.CreateLogger<AnalysisService>(),
            code
        );
        analysisService.RunAnalysis();
    }
}