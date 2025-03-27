Auth Check Analysis Prototype
===

Performs an auth check analysis on the following example code:
```csharp
// Represents a simple GET endpoint with an auth check
class Main
{
    AuthService authService = new AuthService();
    SecretService secretService = new SecretService();
    
    public void GetSecretEndpoint()
    {
        //authService.authCheck<SecretEntity>(); Comment in/out to see analysis result change
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
```

The code used can be changed in the `Program.cs` file.

## Analysis results

1. Analysis output **without auth check** in `GetSecretEndpoint`:
    ```
    dbug: MA_CFGscratchpad.Analysis.AnalysisService[0]
          Following call to GetSecret...
    dbug: MA_CFGscratchpad.Analysis.AnalysisService[0]
          Found secret storage access GetSecret in GetSecret
    dbug: MA_CFGscratchpad.Analysis.AnalysisService[0]
          Skipping non-invocation operation secret of kind LocalReference
    crit: MA_CFGscratchpad.Analysis.AnalysisService[0]
          Required auth type SecretEntity is not checked in GetSecretEndpoint
    ```
2. Analysis result **with auth check** in `GetSecretEndpoint`:
    ```
    dbug: MA_CFGscratchpad.Analysis.AnalysisService[0]
          Found auth check authCheck in GetSecretEndpoint
    dbug: MA_CFGscratchpad.Analysis.AnalysisService[0]
          Following call to GetSecret...
    dbug: MA_CFGscratchpad.Analysis.AnalysisService[0]
          Found secret storage access GetSecret in GetSecret
    dbug: MA_CFGscratchpad.Analysis.AnalysisService[0]
          Skipping non-invocation operation secret of kind LocalReference
    ```
3. Analysis result **with auth check** in `GetSecretEndpoint` **but wrong type**, i.e. string:
    ```
    dbug: MA_CFGscratchpad.Analysis.AnalysisService[0]
          Found auth check authCheck in GetSecretEndpoint
    dbug: MA_CFGscratchpad.Analysis.AnalysisService[0]
          Following call to GetSecret...
    dbug: MA_CFGscratchpad.Analysis.AnalysisService[0]
          Found secret storage access GetSecret in GetSecret
    dbug: MA_CFGscratchpad.Analysis.AnalysisService[0]
          Skipping non-invocation operation secret of kind LocalReference
    crit: MA_CFGscratchpad.Analysis.AnalysisService[0]
          Required auth type SecretEntity is not checked in GetSecretEndpoint
    ```