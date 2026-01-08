# Certificate Manager

A web-based application for managing and generating X.509 digital certificates (SSL/TLS certificates) built with .NET 8.0 and Blazor WebAssembly.

## 🇮🇹 Cos'è questo software? / What is this software?

**Italiano:**
Certificate Manager è un'applicazione web che permette di creare, gestire e convertire certificati digitali X.509 (certificati SSL/TLS). Offre un'interfaccia web intuitiva per generare certificati firmati da una Certificate Authority (CA) root, gestire un database di certificati e scaricare i file in vari formati.

**English:**
Certificate Manager is a web application that allows you to create, manage, and convert X.509 digital certificates (SSL/TLS certificates). It provides an intuitive web interface to generate certificates signed by a root Certificate Authority (CA), manage a certificate database, and download files in various formats.

## ✨ Key Features

- **Certificate Generation**: Create X.509 certificates with custom parameters
  - Common Name (CN)
  - Organization/Company
  - Object Identifier (OID)
  - IP Address
  - DNS names (Subject Alternative Names)
  - Custom expiration dates

- **Certificate Formats**:
  - Generate PFX (PKCS#12) files with private keys
  - Generate CRT (PEM) certificate files
  - Extract CA Root certificates
  - Convert CRT + Key to PFX format

- **Certificate Management**:
  - Store certificate metadata in JSON database
  - List all generated certificates
  - Download certificates (PFX and CRT formats)
  - Calculate SHA-256 hashes for verification
  - Track certificate creation dates and passwords

- **Web Interface**:
  - Modern Blazor WebAssembly UI
  - Microsoft Fluent UI components
  - Certificate overview with data grid
  - Manual certificate creation form
  - Certificate utility for format conversion

- **RESTful API**:
  - Programmatic certificate creation
  - Certificate retrieval
  - File download endpoints
  - SHA hash calculation

## 🏗️ Architecture

The solution consists of several projects:

- **CertificateManager**: ASP.NET Core backend server
  - Hosts the web application
  - Provides REST API endpoints
  - Handles certificate generation logic

- **CertificateManager.Client**: Blazor WebAssembly frontend
  - Modern SPA user interface
  - Interactive certificate management
  - Client-side routing and navigation

- **CertificateCommon**: Shared certificate logic
  - Core certificate generation functionality
  - X.509 certificate operations
  - File management for certificates

- **Common**: Shared utilities
  - Logging infrastructure (Serilog)
  - SHA-256 hash manager
  - HTTP client helpers

- **UT**: Unit tests

## 🔧 Prerequisites

- .NET 8.0 SDK
- A Root CA certificate installed in the Windows Certificate Store
  - Location: `CurrentUser\Root` or `CurrentUser\My`
  - The thumbprint must be configured in `appsettings.json`

## ⚙️ Configuration

Edit `appsettings.json` to configure the Certificate Authority:

```json
{
  "CertificationManager": {
    "CARootThumbPrint": "YOUR_CA_ROOT_THUMBPRINT_HERE",
    "Output": "Output"
  }
}
```

- `CARootThumbPrint`: The thumbprint of your Root CA certificate
- `Output`: Directory where generated certificates will be stored

## 🚀 Building and Running

### Build the solution:
```bash
dotnet build CertificateManager.sln
```

### Run the application:
```bash
cd CertificateManager
dotnet run
```

The application will start on:
- HTTPS: `https://localhost:5001`
- HTTP: `http://localhost:5000`

## 📡 API Endpoints

### Certificate Generation
- `POST /api/Certificate/MakeCertificate` - Create a new certificate
  - Body: Certificate object with CN, OID, Company, Address, DNS, Password, Solution

### Certificate Retrieval
- `GET /api/Certificate/Get?id={id}` - Get certificate by ID
- `GET /api/Certificate/Info` - Get all certificates information
- `GET /api/Certificate/ID?solution={name}` - Get certificate ID by solution name

### File Downloads
- `GET /api/Certificate/downloadPFX?id={id}` - Download PFX certificate file
- `GET /api/Certificate/downloadCRT?id={id}` - Download CA Root CRT file

### Certificate Information
- `POST /api/Certificate/CeritificationInfo` - Get certificate info from uploaded file
- `POST /api/Certificate/CeritificationInfoWithKey` - Get certificate info with private key
- `POST /api/Certificate/CreatePFXFromCRT` - Convert CRT + Key to PFX format

### Hash Calculation
- `GET /api/Certificate/Sha?solutionName={name}&type={type}` - Calculate SHA-256 hash of certificate

## 💻 Usage Examples

### Creating a Certificate via UI:
1. Navigate to the "Certificate Generator" page
2. Fill in the required fields:
   - Solution name (identifier)
   - IP Address or hostname
   - Company name
   - Common Name
   - Password (for PFX encryption)
   - OID (e.g., "1.3.6.1.5.5.7.3.1" for Server Authentication)
3. Add DNS names if needed
4. Click "Make" to generate the certificate

### Viewing Certificates:
1. Navigate to the "Certificates List" page
2. View all generated certificates in a data grid
3. Download PFX or CRT files as needed

### Converting CRT to PFX:
1. Navigate to "Certificate Utility"
2. Upload CRT file
3. Upload private key file
4. Enter password if key is encrypted
5. Enter PFX password
6. Download the converted PFX file

## 📁 Output Structure

Certificates are organized by solution name:
```
Output/
├── {SolutionName}/
│   ├── Certificate.pfx     (PKCS#12 with private key)
│   ├── Certificate.crt     (PEM certificate)
│   ├── private.key         (Private key in PEM format)
│   └── Root.crt            (CA Root certificate)
└── Certificates.Json       (Certificate database)
```

## 🔐 Security Features

- Uses ECDSA with P-256 curve for key generation
- SHA-384 hash algorithm for signatures
- Certificates signed by configured CA Root
- Private keys are encrypted in PFX files
- SHA-256 hash verification for file integrity
- Support for password-protected private keys

## 📝 Certificate Properties

Generated certificates include:
- **Key Usage**: Digital Signature
- **Enhanced Key Usage**: Configurable OID (e.g., Server Authentication)
- **Subject Alternative Names**: IP addresses and DNS names
- **Validity Period**: Configurable, default 10 years
- **Serial Numbers**: Auto-incremented
- **Signature Algorithm**: SHA-384 with ECDSA

## 🛠️ Technologies Used

- **.NET 8.0**: Latest .NET framework
- **ASP.NET Core**: Web server and API
- **Blazor WebAssembly**: Modern SPA framework
- **Microsoft Fluent UI**: UI component library
- **Serilog**: Structured logging
- **System.Security.Cryptography**: Certificate operations

## 📄 License

Please refer to the repository license file.

## 🤝 Contributing

Contributions are welcome! Please ensure all changes maintain backward compatibility and include appropriate tests.

## 🐛 Troubleshooting

### "NO CA Root" error
- Ensure your Root CA certificate is installed in the Windows Certificate Store
- Verify the thumbprint in `appsettings.json` matches your CA certificate
- Check that the CA has a private key attached

### "CA Root without Private Key" error
- The configured Root CA must have its private key available
- Re-import the CA certificate with the private key

### Certificates not generating
- Check the logs in the `LOG/` directory
- Verify the `Output/` directory is writable
- Ensure all required fields are provided

## 📞 Support

For issues and questions, please use the GitHub issue tracker.
