# Contributing to ProtectIT

Thank you for considering contributing to ProtectIT! This document outlines the process and guidelines for contributing to this project.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for everyone.

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in the Issues section
2. If not, create a new issue with a clear title and description
3. Include steps to reproduce the bug
4. Include any relevant screenshots or error messages
5. Describe your environment (OS, browser, etc.)

### Suggesting Enhancements

1. Check if the enhancement has already been suggested in the Issues section
2. If not, create a new issue with a clear title and description
3. Explain why this enhancement would benefit the project
4. Provide examples of how it would work

### Pull Requests

1. Fork the repository
2. Create a new branch from `main` (`git checkout -b feature/your-feature`)
3. Make your changes
4. Run tests to ensure your changes don't break existing functionality
5. Commit your changes with a clear commit message
6. Push to your branch (`git push origin feature/your-feature`)
7. Submit a Pull Request to the `main` branch

## Development Setup

### Prerequisites
- Python 3.8+
- Node.js 16+
- MongoDB

### Setup

1. Clone the repository
```bash
git clone https://github.com/yourusername/ProtectIT.git
cd ProtectIT
```

2. Run the setup script
```bash
chmod +x setup.sh
./setup.sh
```

3. Start the application components
```bash
./start.sh
```

## Coding Guidelines

### Python
- Follow PEP 8 style guide
- Use docstrings for functions and classes
- Maintain test coverage for new features

### JavaScript/React
- Follow ESLint rules
- Use functional components and hooks
- Follow component-based architecture

## Testing

- Run tests before submitting PR
- Add tests for new features
- Ensure all tests pass

## Documentation

- Update README.md if necessary
- Document new features
- Update API documentation for new endpoints

## License

By contributing to ProtectIT, you agree that your contributions will be licensed under the project's MIT License.
