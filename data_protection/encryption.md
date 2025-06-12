# Data Protection Implementation Guide (Cambodia)

## Regulatory Requirements
- **Data Localization**: Critical data must reside within Cambodia
- **Encryption Standards**: Minimum AES-256 for sensitive data
- **PII Handling**: Special rules for:
  - National ID numbers
  - Financial information
  - Health records

## Implementation Examples

### Python: AES-256 Encryption
```python
from cryptography.fernet import Fernet
import base64

# Generate key (store securely in Cambodia)
key = Fernet.generate_key()
cipher = Fernet(key)

# Encrypt Khmer Unicode text
khmer_text = "ព័ត៌មានរបស់អតិថិជន".encode('utf-8')
encrypted = cipher.encrypt(khmer_text)

# Decrypt
decrypted = cipher.decrypt(encrypted).decode('utf-8')
```

### Docker: Secure Data Container
```dockerfile
FROM alpine:latest

# Install encryption tools
RUN apk add --no-cache gnupg openssl

# Create secure volume for Cambodian data
VOLUME /secure-data

# Set strict permissions
RUN chmod 700 /secure-data
```

## Compliance Checklist
- [ ] Data classification policy (Khmer/English)
- [ ] Encryption key management procedure
- [ ] Data breach response plan aligned with Cambodian law
- [ ] Staff training on Khmer PII handling