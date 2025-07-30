# Contributing to Ghostkey Server

Thank you for your interest in contributing to Ghostkey Server! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Security Considerations](#security-considerations)
- [Documentation](#documentation)
- [Community](#community)

## Code of Conduct

This project adheres to a code of conduct that we expect all contributors to follow. Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## Getting Started

### Prerequisites

- Go 1.21 or later
- Git
- Docker (for containerized development)
- Make (optional, for convenience scripts)

### Development Setup

1. **Fork and Clone**
   ```bash
   git clone https://github.com/your-username/Ghostkey_Server.git
   cd Ghostkey_Server
   ```

2. **Install Dependencies**
   ```bash
   go mod download
   ```

3. **Set Environment Variables**
   ```bash
   export SECRET_KEY="your_development_secret_key_minimum_32_characters_long"
   ```

4. **Run the Application**
   ```bash
   go run .
   ```

5. **Run Tests**
   ```bash
   go test ./...
   ```

## How to Contribute

### Types of Contributions

We welcome various types of contributions:

- **Bug Reports**: Help us identify and fix issues
- **Feature Requests**: Suggest new functionality
- **Code Contributions**: Implement features or fix bugs
- **Documentation**: Improve or add documentation
- **Testing**: Add or improve tests
- **Security**: Report security vulnerabilities (see [SECURITY.md](SECURITY.md))

### Before You Start

1. **Check Existing Issues**: Look for existing issues or discussions
2. **Create an Issue**: For significant changes, create an issue first to discuss
3. **Get Feedback**: Engage with maintainers and community members

## Pull Request Process

### 1. Prepare Your Changes

- **Branch**: Create a feature branch from `main`
  ```bash
  git checkout -b feature/your-feature-name
  ```

- **Commit Messages**: Use conventional commit format
  ```bash
  git commit -m "feat: add user authentication endpoint"
  git commit -m "fix: resolve database connection issue"
  git commit -m "docs: update API documentation"
  ```

### 2. Before Submitting

- **Test**: Ensure all tests pass
  ```bash
  go test ./...
  ```

- **Lint**: Run linting tools
  ```bash
  golangci-lint run
  ```

- **Format**: Format your code
  ```bash
  go fmt ./...
  ```

- **Security**: Run security checks
  ```bash
  gosec ./...
  ```

### 3. Submit Pull Request

- Fill out the PR template completely
- Reference related issues
- Provide clear description of changes
- Include tests for new functionality
- Update documentation if needed

### 4. Review Process

- **Automated Checks**: CI/CD pipeline will run automatically
- **Code Review**: Maintainers will review your code
- **Feedback**: Address any requested changes
- **Approval**: PR will be merged after approval

## Coding Standards

### Go Style Guide

Follow these guidelines:

- **Go Standards**: Follow official Go conventions
- **gofmt**: Always format code with `gofmt`
- **golint**: Address linting issues
- **Error Handling**: Always handle errors appropriately
- **Documentation**: Document public functions and types

### Code Organization

```
.
├── main.go           # Application entry point
├── config.go         # Configuration management
├── models.go         # Data models
├── routes.go         # HTTP route handlers
├── middleware.go     # HTTP middleware
├── sync.go          # Synchronization logic
├── cluster.go       # Clustering functionality
├── errors.go        # Error handling
└── *_test.go        # Test files
```

### Naming Conventions

- **Variables**: camelCase (`userName`, `secretKey`)
- **Functions**: camelCase (`getUserByID`, `validateInput`)
- **Constants**: UPPER_SNAKE_CASE (`MAX_RETRY_ATTEMPTS`)
- **Types**: PascalCase (`User`, `ESPDevice`)

### Error Handling

```go
// Good
result, err := someFunction()
if err != nil {
    return fmt.Errorf("failed to execute function: %w", err)
}

// Use standardized error responses
RespondInternalError(c, "Failed to process request")
```

### Security Guidelines

- **Input Validation**: Always validate and sanitize inputs
- **SQL Injection**: Use parameterized queries
- **Authentication**: Verify authentication for protected endpoints
- **Secrets**: Never hardcode secrets or credentials
- **Logging**: Don't log sensitive information

## Testing Guidelines

### Test Structure

- **Unit Tests**: Test individual functions/methods
- **Integration Tests**: Test component interactions
- **End-to-End Tests**: Test complete workflows

### Writing Tests

```go
func TestUserAuthentication(t *testing.T) {
    // Arrange
    user := &User{Username: "testuser"}
    user.SetPassword("password123")
    
    // Act
    result := user.CheckPassword("password123")
    
    // Assert
    if !result {
        t.Error("Expected password check to succeed")
    }
}
```

### Test Coverage

- Aim for minimum 80% test coverage
- Test both success and failure scenarios
- Mock external dependencies
- Test edge cases and error conditions

## Security Considerations

### Reporting Security Issues

- **Never** create public issues for security vulnerabilities
- Follow our [Security Policy](SECURITY.md)
- Report privately through GitHub Security Advisories

### Security Best Practices

- **Authentication**: Use strong authentication mechanisms
- **Authorization**: Implement proper access controls
- **Input Validation**: Validate all inputs
- **Encryption**: Use encryption for sensitive data
- **Dependencies**: Keep dependencies updated

## Documentation

### Types of Documentation

- **Code Comments**: Document complex logic
- **API Documentation**: Document endpoints and responses
- **README**: Keep README.md updated
- **Architecture**: Document system design decisions

### Documentation Standards

- **Clear**: Write clear, concise documentation
- **Examples**: Provide examples where helpful
- **Up-to-date**: Keep documentation synchronized with code
- **Accessible**: Use simple language

## Development Workflow

### Git Workflow

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request
6. Address review feedback
7. Merge after approval

### Commit Guidelines

Use conventional commits:

- `feat:` New features
- `fix:` Bug fixes
- `docs:` Documentation changes
- `style:` Code style changes
- `refactor:` Code refactoring
- `test:` Adding or updating tests
- `chore:` Maintenance tasks

### Release Process

- **Semantic Versioning**: We use semantic versioning (x.y.z)
- **Release Notes**: Maintain detailed release notes
- **Security Updates**: Security fixes get priority releases

## Community

### Communication Channels

- **GitHub Issues**: For bugs and feature requests
- **GitHub Discussions**: For general discussions
- **Pull Requests**: For code contributions

### Getting Help

- Check existing documentation
- Search existing issues
- Create a new issue with detailed information
- Join community discussions

### Recognition

We value all contributions and will recognize contributors through:

- Contributors list in README
- Release notes acknowledgments
- GitHub contributor statistics

## Questions?

If you have questions about contributing, please:

1. Check this document
2. Search existing issues and discussions
3. Create a new discussion or issue
4. Reach out to maintainers

Thank you for contributing to Ghostkey Server! 🚀
