# Security Configuration Guide

This document outlines the security features and best practices for deploying the Ghostkey Server.

## Security Features Implemented

### 1. Authentication & Authorization
- **Strong Secret Key Validation**: Enforces minimum 32 characters with mixed character types
- **Password Hashing**: Uses bcrypt for secure password storage
- **Session Security**: HttpOnly, Secure (in production), SameSite strict mode
- **Session Regeneration**: Prevents session fixation attacks
- **Rate Limiting**: Protects against brute force attacks

### 2. Input Validation & Sanitization
- **SQL Injection Protection**: GORM ORM with parameterized queries
- **XSS Prevention**: Input sanitization and Content Security Policy
- **Directory Traversal Protection**: File path validation
- **File Upload Security**: Type validation, size limits, dangerous extension blocking

### 3. Security Headers
- **X-Content-Type-Options**: nosniff
- **X-Frame-Options**: DENY
- **X-XSS-Protection**: 1; mode=block
- **Content-Security-Policy**: Restrictive policy
- **Strict-Transport-Security**: HSTS for HTTPS
- **Referrer-Policy**: strict-origin-when-cross-origin

### 4. Network Security
- **CORS Configuration**: Controlled cross-origin access
- **Request Size Limiting**: 10MB maximum request size
- **TLS Support**: HTTPS enforcement in production

### 5. Audit & Monitoring
- **Security Event Logging**: Authentication attempts, device access, user registration
- **Audit Trail**: Timestamped security events with IP addresses
- **Rate Limit Monitoring**: Failed request tracking

### 6. Container Security
- **Non-root User**: Runs as unprivileged user (UID 65532)
- **Read-only Filesystem**: Minimal write access
- **Dropped Capabilities**: ALL capabilities dropped
- **Resource Limits**: Memory and CPU constraints
- **Secure Networking**: Isolated bridge network

### 7. Database Security
- **File Permissions**: Restricted to owner only (0600)
- **Connection Pooling**: Configured with limits
- **Backup Encryption**: Automatic encrypted backups

## Deployment Security Checklist

### Before Deployment
- [ ] Generate a strong secret key (use `openssl rand -hex 32`)
- [ ] Set `SECRET_KEY` environment variable
- [ ] Configure TLS certificates for HTTPS
- [ ] Set `GIN_MODE=release` for production
- [ ] Review and configure CORS allowed origins

### Environment Variables
```bash
# Required
SECRET_KEY=your-strong-secret-key-here

# Recommended
GIN_MODE=release
```

### File Permissions
```bash
# Database files
chmod 600 data.db
chmod 600 backups/*.db

# Secret files
chmod 600 .secrets
```

### Network Configuration
- Use HTTPS in production (port 443)
- Configure reverse proxy with security headers
- Restrict network access to necessary ports only
- Use firewall rules to limit access

### Monitoring
- Monitor audit logs for suspicious activity
- Set up alerts for failed authentication attempts
- Track rate limit violations
- Monitor file upload activities

## Security Best Practices

### 1. Secret Management
- Never use default secret keys
- Store secrets in environment variables or secret management systems
- Rotate secrets regularly
- Use different secrets for different environments

### 2. Network Security
- Always use HTTPS in production
- Configure proper firewall rules
- Use VPN or private networks when possible
- Implement network segmentation

### 3. Access Control
- Implement principle of least privilege
- Use strong passwords for user accounts
- Regularly audit device registrations
- Monitor command execution logs

### 4. Data Protection
- Encrypt sensitive data at rest
- Use secure file transfer protocols
- Implement data retention policies
- Regular security backups

### 5. Monitoring & Incident Response
- Set up centralized logging
- Implement real-time security monitoring
- Establish incident response procedures
- Regular security assessments

## Known Security Considerations

### 1. File Uploads
- Files are stored temporarily on disk
- Consider implementing virus scanning
- Monitor disk usage for DoS attacks

### 2. Device Authentication
- Device secret keys are stored in database
- Consider implementing certificate-based authentication
- Monitor device communication patterns

### 3. Command Execution
- Commands are stored in plaintext
- Consider implementing command validation
- Monitor for suspicious command patterns

## Reporting Security Issues

If you discover a security vulnerability, please:
1. Do not create a public issue
2. Contact the maintainers privately
3. Provide detailed information about the vulnerability
4. Allow time for fix before public disclosure

## Security Updates

- Regularly update Go dependencies
- Monitor security advisories for used libraries
- Update container base images
- Apply security patches promptly