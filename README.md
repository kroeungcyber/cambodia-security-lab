# Cambodia Security Lab

A comprehensive cybersecurity platform designed for Cambodian government and enterprise requirements.

## Key Security Features

### Data Protection
- AES-256-GCM encryption with PBKDF2 key derivation
- Secure password policies with Khmer translations
- Detailed security logging and monitoring

### Infrastructure Security
- Docker containers with security best practices
- HTTPS enforcement with modern TLS configurations
- Cloud-ready architecture (AWS/GCP/Azure compatible)

### Compliance
- Aligned with ASEAN cybersecurity frameworks
- Meets Cambodian government security requirements
- Regular security audits and penetration testing

## Getting Started

### Prerequisites
- Docker 20.10+
- Python 3.9+
- Valid SSL certificates for production

### Installation
```bash
docker-compose up -d --build
```

### Security Configuration
1. Set environment variables in `.env`:
```
ENCRYPTION_KEY=your_secure_key_here
ALLOWED_IPS=192.168.1.0/24,203.189.0.0/16
```

2. Configure monitoring in `docs/grafana/`

## Security Documentation
- [Data Protection](data_protection/encryption.md)
- [Cloud Security Benchmark](cloud/multi-cloud-benchmark.md)
- [ASEAN Compliance](grc/asean-compliance.md)

## Threat Protection
- Phishing awareness training materials
- Regular vulnerability scanning
- Incident response procedures

## For Cambodian Organizations
- Contact Cambodia CERT for security advisories
- Report incidents to MPTC
- Follow National Cybersecurity Policy guidelines

## Maintenance
- Monthly security updates
- Quarterly penetration tests
- Annual compliance reviews

## License
This project is licensed under the Cambodian Government Secure Development License.