using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.FlowAnalysis;
using Microsoft.CodeAnalysis.Operations;
using Microsoft.Extensions.Logging;

namespace MA_CFGscratchpad.Analysis;

public class AnalysisService
{
    // Settings
    private const string SecretStorageClassName = "DatabaseService";
    private const string EndpointClassName = "Main";
    private const string AuthCheckMethodName = "authCheck";
    private const string AuthCheckClassName = "AuthService";

    // Filled in constructor
    private readonly ILogger _logger;
    private readonly SyntaxNode _root;
    private readonly CSharpCompilation _compilation;
    private readonly SemanticModel _semanticModel;
    private readonly INamedTypeSymbol _secretStorageClassSymbol;
    private readonly IMethodSymbol _authCheckMethodSymbol;

    /// <summary>
    ///     Prepares custom analysis.
    /// </summary>
    /// <param name="code">The code to analyze.</param>
    public AnalysisService(ILogger logger, string code)
    {
        _logger = logger;

        // Prepare compilation and semantic model for analysis
        var syntaxTree = CSharpSyntaxTree.ParseText(code);
        _compilation = CSharpCompilation.Create("Example")
            .AddReferences(MetadataReference.CreateFromFile(typeof(object).Assembly.Location))
            .AddSyntaxTrees(syntaxTree);
        _root = syntaxTree.GetRoot();
        _semanticModel = _compilation.GetSemanticModel(syntaxTree);

        // Retrieve the secret storage class type
        var secretStorageClassDeclarationSyntax = _root.DescendantNodes()
            .OfType<ClassDeclarationSyntax>()
            .FirstOrDefault(cd => cd.Identifier.Text == SecretStorageClassName)!;
        _secretStorageClassSymbol = _semanticModel.GetDeclaredSymbol(secretStorageClassDeclarationSyntax)!;

        // Retrieve the auth check method type
        var authCheckClassDeclarationSyntax = _root.DescendantNodes()
            .OfType<ClassDeclarationSyntax>()
            .FirstOrDefault(cd => cd.Identifier.Text == AuthCheckClassName)!;
        var authCheckMethodDeclarationSyntax = authCheckClassDeclarationSyntax.DescendantNodes()
            .OfType<MethodDeclarationSyntax>()
            .FirstOrDefault(md => md.Identifier.Text == AuthCheckMethodName)!;
        _authCheckMethodSymbol = _semanticModel.GetDeclaredSymbol(authCheckMethodDeclarationSyntax)!;
    }

    /// <summary>
    ///     Runs the basic analysis searching for missing auth checks.
    /// </summary>
    public void RunAnalysis()
    {
        var endpointMethods = RetrieveEndpointMethods();
        foreach (var endpointMethod in endpointMethods)
        {
            var visitedMethods = new HashSet<IMethodSymbol>(SymbolEqualityComparer.Default);
            var requiredAuthTypes = new HashSet<ITypeSymbol>(SymbolEqualityComparer.Default);
            var actuallyCheckedAuthTypes = new HashSet<ITypeSymbol>(SymbolEqualityComparer.Default);
            RetrieveRequiredAndActuallyDoneAuthChecksForMethod(
                endpointMethod,
                visitedMethods,
                requiredAuthTypes,
                actuallyCheckedAuthTypes
            );

            // Check whether all required auth types are actually checked
            foreach (var requiredAuthType in requiredAuthTypes)
            {
                if (!actuallyCheckedAuthTypes.Contains(requiredAuthType))
                {
                    _logger.LogCritical(
                        "Required auth type {} is not checked in {}",
                        requiredAuthType.Name,
                        endpointMethod.Identifier.Text
                    );
                }
            }
        }
    }

    /// <summary>
    ///     Returns all "endpoint" methods (i.e. API endpoints, for now just "Main" class methods).
    /// </summary>
    private IEnumerable<MethodDeclarationSyntax> RetrieveEndpointMethods()
    {
        var endpointClassDeclarationSyntax = _root.DescendantNodes()
            .OfType<ClassDeclarationSyntax>()
            .FirstOrDefault(cd => cd.Identifier.Text == EndpointClassName)!;
        return endpointClassDeclarationSyntax.DescendantNodes().OfType<MethodDeclarationSyntax>();
    }

    /// <summary>
    ///     Performs a control flow analysis on the given method.
    ///     Saves all auth checks found in the method's control flow
    ///     and all sensitive data accesses that require auth checks.
    ///     <remarks>
    ///         Does not check whether these match - this has to be done by the caller!
    ///     </remarks>
    /// </summary>
    /// <param name="curMethod">The method to analyze.</param>
    /// <param name="visitedMethods">
    ///     All methods that already have been visited in this control flow; used to avoid infinite recursion.
    /// </param>
    /// <param name="requiredAuthTypes">
    ///     A list of types that are accessed in the control flow; these should have a corresponding auth check.
    /// </param>
    /// <param name="actuallyCheckedAuthTypes">A list of all types that actually are auth checked.</param>
    private void RetrieveRequiredAndActuallyDoneAuthChecksForMethod(
        MethodDeclarationSyntax curMethod,
        HashSet<IMethodSymbol> visitedMethods,
        HashSet<ITypeSymbol> requiredAuthTypes,
        HashSet<ITypeSymbol> actuallyCheckedAuthTypes)
    {
        var curMethodSymbol = _semanticModel.GetDeclaredSymbol(curMethod)!;

        // Avoid infinite recursion or re-analysis
        if (!visitedMethods.Add(curMethodSymbol))
        {
            return;
        }

        // Create ControlFlowGraph for the current method body and traverse it
        var cfg = ControlFlowGraph.Create(curMethod, _compilation.GetSemanticModel(curMethod.SyntaxTree))!;
        foreach (var block in cfg.Blocks)
        {
            var operations = block.Operations;
            if (block.BranchValue is not null)
            {
                operations = operations.Add(block.BranchValue);
            }

            foreach (var operation in operations)
            {
                // Filters for expressions that contain a method invocation
                IInvocationOperation? invocationOperation = null;
                foreach (var childOperation in operation.ChildOperations)
                {
                    if (childOperation is IInvocationOperation invocation)
                    {
                        invocationOperation = invocation;
                    }
                }

                if (invocationOperation is null)
                {
                    _logger.LogDebug(
                        "Skipping non-invocation operation {} of kind {}",
                        operation.Syntax,
                        operation.Kind
                    );
                    continue;
                }

                var targetMethod = invocationOperation.TargetMethod;
                var targetMethodClass = (targetMethod.MethodKind == MethodKind.Constructor
                    ? targetMethod.ReturnType
                    : targetMethod.ReceiverType)!;

                // Call to auth check
                if (SymbolEqualityComparer.Default.Equals(targetMethod.OriginalDefinition, _authCheckMethodSymbol))
                {
                    _logger.LogDebug(
                        "Found auth check {} in {}",
                        targetMethod.Name,
                        curMethodSymbol.Name
                    );

                    // The secret type to be checked is for now passed as a type parameter
                    actuallyCheckedAuthTypes.Add(targetMethod.TypeArguments.First());

                    // Found end of the call chain (auth check)
                    continue;
                }

                // Call to secret storage class
                if (SymbolEqualityComparer.Default.Equals(targetMethodClass, _secretStorageClassSymbol))
                {
                    _logger.LogDebug(
                        "Found secret storage access {} in {}",
                        targetMethod.Name,
                        curMethodSymbol.Name
                    );

                    // For now, assume that the return type is the required auth type
                    requiredAuthTypes.Add(targetMethod.ReturnType);

                    // Found end of the call chain (secret storage access)
                    continue;
                }

                // Any other invocation -> Recursively analyze the target method
                _logger.LogDebug(
                    "Following call to {}...",
                    invocationOperation.TargetMethod.Name
                );
                if (targetMethod.DeclaringSyntaxReferences.Length > 0)
                {
                    var declaringReference = invocationOperation.TargetMethod.DeclaringSyntaxReferences.First();
                    var declaringNode = declaringReference.GetSyntax() as MethodDeclarationSyntax;

                    RetrieveRequiredAndActuallyDoneAuthChecksForMethod(
                        declaringNode!,
                        visitedMethods,
                        requiredAuthTypes,
                        actuallyCheckedAuthTypes
                    );
                }
            }
        }
    }
}