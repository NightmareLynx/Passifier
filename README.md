![image alt](https://github.com/NightmareLynx/Passifier/blob/282437a448ca311a1431c0000bf088701921edc1/Banner.png)
# Passifier

**Advanced CLI Password Strength Auditor with Entropy Analysis**

A comprehensive password security analysis tool designed for cybersecurity professionals, penetration testers, and security awareness training.

[![Python Version](https://img.shields.io/badge/python-3.6%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-focused-red.svg)](https://github.com/yourusername/passifier)

## Features

### Advanced Analysis Engine

- **Dual Entropy Calculations**: Mathematical entropy and Shannon entropy analysis
- **Character Set Detection**: Comprehensive analysis of character diversity
- **Vulnerability Assessment**: Detects common passwords, patterns, and weaknesses
- **Time-to-Crack Estimation**: Realistic crack time calculations using modern GPU speeds

### Professional Reporting

- **Color-coded Strength Levels**: Visual strength indicators (Very Weak to Very Strong)
- **Detailed Security Reports**: Comprehensive vulnerability breakdowns
- **Statistical Summaries**: Distribution charts and aggregate metrics
- **Export Capabilities**: JSON format for integration with other tools

### User Experience

- **Batch Processing**: Analyze large password lists efficiently
- **Interactive Mode**: Real-time single password analysis
- **Progress Tracking**: Visual progress indicators for large datasets
- **Customizable Output**: Adjustable result limits and formats

## Quick Start

### Prerequisites

- Python 3.6 or higher
- No external dependencies required (uses only standard library)

### Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/NightmareLynx/passifier.git
   cd Passifier
   ```
2. **Make executable:**

   ```bash
   chmod +x Passifier.py
   ```
3. **Run the tool:**

   ```bash
   python3 Passifier.py --help
   ```

## Usage Examples

### Batch Analysis

Analyze a list of passwords from a file:

```bash
python3 Passifier.py -f passwords.txt -o audit_report.json
```

### Interactive Mode

Analyze individual passwords interactively:

```bash
python3 Passifier.py -i
```

### Custom Analysis

Analyze with specific output limits:

```bash
python3 Passifier.py -f rockyou.txt -l 25 --no-progress
```

## Command Line Options

| Option                | Description                                   |
| --------------------- | --------------------------------------------- |
| `-f, --file`        | Password list file path                       |
| `-o, --output`      | Export results to JSON file                   |
| `-l, --limit`       | Limit detailed results display (default: 10)  |
| `-i, --interactive` | Interactive mode for single password analysis |
| `--no-progress`     | Disable progress indicator                    |
| `-h, --help`        | Show help message                             |

## Sample Output

```
╔══════════════════════════════════════════════════════════════════════════════════╗
║                                  PASSIFIER                                       ║
║                        CLI PASSWORD STRENGTH AUDITOR                             ║
║                     Advanced Entropy & Security Analysis                         ║
╚══════════════════════════════════════════════════════════════════════════════════╝

 AUDIT SUMMARY
════════════════════════════════════════════════════════════════════════════════════
Total Passwords Analyzed: 1000
Average Entropy: 42.3 bits
Average Length: 8.7 characters
Passwords with Vulnerabilities: 847 (84.7%)

Strength Distribution:
Very Strong :     23 ( 2.3%) ██
Strong      :    130 (13.0%) ███████
Medium      :    201 (20.1%) ██████████
Weak        :    346 (34.6%) █████████████████
Very Weak   :    300 (30.0%) ███████████████
```

## Use Cases

### Cybersecurity Professionals

- **Penetration Testing**: Audit client password policies
- **Security Assessments**: Evaluate organizational password strength
- **Compliance Audits**: Generate detailed security reports

### Educational & Training

- **Security Awareness**: Demonstrate password vulnerabilities
- **Training Materials**: Create educational content about password security
- **Research**: Study password patterns and entropy distributions

### Personal Security

- **Password Auditing**: Check your own password strength
- **Security Improvement**: Get actionable recommendations
- **Awareness Building**: Understand password security concepts

## Entropy Calculation Methods

Passifier uses two complementary entropy calculation methods:

1. **Mathematical Entropy**: Based on character space and length

   ```
   Entropy = log₂(character_space) × password_length
   ```
2. **Shannon Entropy**: Based on character frequency distribution

   ```
   H(X) = -Σ P(x) × log₂P(x)
   ```

### Authorized Use:

- Testing passwords you own or have explicit permission to audit
- Educational cybersecurity training and awareness
- Legitimate penetration testing with proper authorization
- Personal password strength assessment

### Unauthorized Use:

- Do not use on passwords without explicit permission
- Do not use for malicious purposes or unauthorized access
- Respect privacy and legal boundaries

**The developers are not responsible for misuse of this tool. Users must comply with all applicable laws and regulations.**

## Contributing

We welcome contributions from the cybersecurity community!

### Areas for Contribution:

- Additional entropy calculation methods
- New vulnerability detection patterns
- Performance optimizations
- Documentation improvements
- Localization support

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**NightmareLynx**

- Cybersecurity Enthusiast & Educator
- Security Content Creator (Dev.to, Medium)
- Mission: Spreading cybersecurity awareness through education

### Connect with me:

- GitHub: [@NightmareLynx](https://github.com/NightmareLynx)
- Dev.to: [@NightmareLynx](https://dev.to/nightmare-lynx)
- Medium: [@NightmareLynx](https://medium.com/@Nightmare-Lynx)

## Acknowledgments

- Cybersecurity community for inspiration and feedback
- Open source contributors who make tools like this possible
- Educational institutions promoting ethical hacking practices

## Ethical Usage & Disclaimer

**IMPORTANT**: This tool is designed for educational and legitimate security testing purposes only.

"SHHHH. Remember No One Is 100% Secure Ever!"
