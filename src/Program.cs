using System.Collections.Concurrent;
using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Security.Cryptography.Xml;

namespace FuctSigChecker;

public class Program
{
    private static readonly ConcurrentBag<FileCheckResult> Results = [];
    private static readonly HashSet<string> KnownCertificateThumbs = [];

    public async static Task<int> Main(string[] args)
    {
        if (args.Length != 1)
        {
            Console.WriteLine("Path is required");
            return 1;
        }

        var targetPath = Path.GetFullPath(args[0]);

        if (!LoadCertificates())
        {
            return 1;
        }

        if (KnownCertificateThumbs.Count == 0)
        {
            Console.WriteLine("No certificates were loaded. Exiting");
            return 1;
        }

        var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            Console.WriteLine("Canceling on user request...");
            cts.Cancel();
            e.Cancel = true;
        };

        var paths = Directory.EnumerateFiles(targetPath, "*.zip", SearchOption.AllDirectories).ToList();
        if (paths.Count == 0)
        {
            Console.WriteLine("No files matching *.zip found in the destination dir");
            return 0;
        }

        Console.WriteLine($"Found {paths.Count}. Starting...");

        try
        {
            await Parallel.ForEachAsync(paths,
                new ParallelOptions
                {
                    CancellationToken = cts.Token
                },
                async (item, ct) =>
                {
                    var result = await ProcessFile(item, ct);
                    Results.Add(result);
                });
        }
        catch (OperationCanceledException)
        {
            PrintResults(paths);
            Console.WriteLine("Canceled on user request");
            return 1;
        }
        catch (Exception e)
        {
            PrintResults(paths);
            Console.WriteLine("Canceling due to unexpected error:");
            Console.WriteLine(e);

            return 1;
        }

        Console.WriteLine("Finished successfully");
        PrintResults(paths);
        return 0;
    }

    public static async Task<FileCheckResult> ProcessFile(string filePath, CancellationToken cancelToken)
    {
        var result = new FileCheckResult
        {
            Path = filePath
        };

        try
        {
            var fileBytes = await File.ReadAllBytesAsync(filePath, cancelToken);
            using var ms = new MemoryStream(fileBytes);
            using var archive = new ZipArchive(ms, ZipArchiveMode.Read);

            if (archive.Entries.Count != 2)
            {
                return result.Skipped();
            }

            var sigEntry = archive.Entries.Where(r => r.FullName.StartsWith("semnatura_")).FirstOrDefault();
            if (sigEntry == null)
            {
                return result.Skipped();
            }

            var docEntry = archive.Entries.Where(r => r.FullName != sigEntry.FullName).FirstOrDefault();
            if (docEntry == null)
            {
                return result.Skipped();
            }

            var docBytes = ReadEntryBytes(docEntry);
            var docSha = MakeSha256(docBytes);

            using var sigStream = sigEntry.Open();
            var xmlSig = new XmlDocument();
            xmlSig.PreserveWhitespace = true;
            xmlSig.Load(sigStream);

            var digestValNode = xmlSig.SelectSingleNode("//ds:DigestValue", CreateNamespaceManager(xmlSig));
            if (digestValNode == null)
            {
                return result.Skipped();
            }

            var certNode = xmlSig.SelectSingleNode("//ds:X509Certificate", CreateNamespaceManager(xmlSig));
            if (certNode == null)
            {
                return result.Skipped();
            }

            var cert = new X509Certificate2(Convert.FromBase64String(certNode.InnerText));
            var pubKey = cert.GetRSAPublicKey();
            if (pubKey == null)
            {
                throw new Exception("Failed to get RSA pub key from cert");
            }
            
            var signedXml = new SignedXml();

            // it's important that we load it rather than use the constructor
            signedXml.LoadXml(xmlSig.DocumentElement!);

            result.PassedDigestCheck = docSha == digestValNode.InnerText;
            result.PassedSignatureCheck = SignatureVerifier.CallCheckSignedInfo(signedXml, pubKey);
            result.PassedCertificateCheck = KnownCertificateThumbs.Contains(cert.Thumbprint);
        }
        catch (Exception e)
        {
            result.Exception = e;
            result.Status = ValidationStatus.Error;
            return result;
        }

        result.Status = result.PassedDigestCheck && result.PassedCertificateCheck && result.PassedSignatureCheck
            ? ValidationStatus.CompletedPassed
            : ValidationStatus.CompletedFailed;

        return result;
    }

    public static bool LoadCertificates()
    {
        try
        {
            var asm = typeof(Program).Assembly;
            var names = asm.GetManifestResourceNames();
            var certNames = names.Where(r => r.Contains(".certs."));
            foreach (var certName in certNames)
            {
                var stream = asm.GetManifestResourceStream(certName);
                if (stream == null)
                {
                    throw new Exception($"Could not load stream for resource {certName}");
                }

                using var ms = new MemoryStream();
                stream.CopyTo(ms);

                var cert = new X509Certificate2(ms.ToArray());
                KnownCertificateThumbs.Add(cert.Thumbprint);
            }
        }
        catch (Exception e)
        {
            Console.WriteLine("Failed while loading certificates:");
            Console.WriteLine(e);
            return false;
        }

        return true;
    }

    public static void PrintResults(List<string> candidates)
    {
        var results = Results.ToArray();
        var skippedCount = 0;
        var completedPassedCount = 0;
        var errorEntries = new List<FileCheckResult>();
        var completedFailedEntries = new List<FileCheckResult>();

        foreach (var entry in results)
        {
            switch (entry.Status)
            {
                case ValidationStatus.Skipped:
                    skippedCount += 1;
                    continue;
                case ValidationStatus.Error:
                    errorEntries.Add(entry);
                    continue;
                case ValidationStatus.CompletedPassed:
                    completedPassedCount += 1;
                    continue;
                case ValidationStatus.CompletedFailed:
                    completedFailedEntries.Add(entry);
                    continue;
                default:
                    throw new ArgumentOutOfRangeException();
            }
        }

        Console.WriteLine($"Matched {candidates.Count} files. Checked {results.Length} files:");
        Console.WriteLine($"Skipped: {skippedCount}/{results.Length}");
        Console.WriteLine($"Failed: {completedFailedEntries.Count}/{results.Length}");
        Console.WriteLine($"Passed: {completedPassedCount}/{results.Length}");

        foreach (var errorEntry in errorEntries)
        {
            Console.WriteLine($"Error during check for: {errorEntry.Path}");
            Console.WriteLine(errorEntry.Exception.ToString());
        }

        foreach (var failedEntry in completedFailedEntries)
        {
            Console.WriteLine($"Failed validation for: {failedEntry.Path}. "
                              + $"Passed digest: {failedEntry.PassedDigestCheck}; "
                              + $"Passed sig: {failedEntry.PassedSignatureCheck}; "
                              + $"Passed cert: {failedEntry.PassedCertificateCheck}");
        }
    }

    public static string MakeSha256(byte[] bytes)
    {
        var inputHash = SHA256.HashData(bytes);
        return Convert.ToBase64String(inputHash);
    }

    public static XmlNamespaceManager CreateNamespaceManager(XmlDocument doc)
    {
        var nsmgr = new XmlNamespaceManager(doc.NameTable);
        nsmgr.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
        return nsmgr;
    }

    public static byte[] ReadEntryBytes(ZipArchiveEntry entry)
    {
        using var f = entry.Open();
        using var ms = new MemoryStream();
        f.CopyTo(ms);

        return ms.ToArray();
    }
}

public static class SignatureVerifier
{
    private static readonly MethodInfo CheckSignedInfoMethod;

    static SignatureVerifier()
    {
        CheckSignedInfoMethod = typeof(SignedXml).GetMethod("CheckSignedInfo",
            BindingFlags.NonPublic | BindingFlags.Instance,
            null,
            new[] { typeof(AsymmetricAlgorithm) },
            null);

        if (CheckSignedInfoMethod == null)
        {
            throw new InvalidOperationException("CheckSignedInfo method not found");
        }
    }

    public static bool CallCheckSignedInfo(SignedXml target, AsymmetricAlgorithm key)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(key);

        var result = CheckSignedInfoMethod.Invoke(target, [key]);
        
        return (bool)result;
    }
}

public class FileCheckResult
{
    public string Path { get; set; }
    public ValidationStatus Status { get; set; }
    public bool PassedDigestCheck { get; set; }
    public bool PassedCertificateCheck { get; set; }
    public bool PassedSignatureCheck { get; set; }
    public Exception Exception { get; set; }

    public FileCheckResult Skipped()
    {
        Status = ValidationStatus.Skipped;
        return this;
    }
}

public enum ValidationStatus
{
    Skipped,
    Error,
    CompletedPassed,
    CompletedFailed
}