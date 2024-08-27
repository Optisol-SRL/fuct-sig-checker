# FuctSigChecker

Example C# code demonstrating signature verification for Romanian eInvoice XML documents ("e-Factura").
While only provided for demonstration purposes, this project can be used to validate signatures for all invoices in a directory, enclosed in their original .zip archive.

To run:

1. Make sure you have the .NET 8 SDK installed 

2. `dotnet build`

3. `dotnet run <path>`

Mentions:
- This is not an official tool, we have no government affiliation and we provide no guarantees of correctness.
- See [Informații tehnice e-Factura](https://mfinante.gov.ro/web/efactura/informatii-tehnice) for the official validator
- Similar to the official version, we've embedded the certificates and strictly check against them without involving the OS certificate store. This means that revocations will have no effect. If/when new certificates are used to sign eInvoices, this tool will return false negatives.

Given that the XML sig validator built into .NET can't handle these detached signatures, we check for it ourselves in 3 steps:
- the digest is the SHA256 of the invoice XML file
- we call into `SignedXml` via reflection to check that the signature envelope hasn't been tampered with
- we check the certificate in the signature file against a list of known certificates 