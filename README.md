# Anti-Phishing Protection System

A Python package for educational institutions to protect students from phishing attempts and malicious URLs.

## Features

- URL safety checking against known phishing patterns
- Student authentication system
- URL check history logging
- Command-line interface
- Firebase integration for administrators

## Installation

```bash
pip install anti-phishing

or

# Install pipx if not already installed
sudo apt install pipx

# Install the package using pipx
pipx install git+https://github.com/rafat1999/anti_phishing.git
```

## Usage

### For Students

Simply run the command:

```bash
pipx ensurepath
anti-phishing
```

The system will run in demo mode, allowing you to check URLs against common phishing patterns.

### For Administrators

1. Set up a Firebase project and download your service account key
2. Set the environment variable:
   ```bash
   export FIREBASE_CREDENTIALS=/path/to/serviceAccountKey.json
   ```
3. Run the system:
   ```bash
   pipx ensurepath
   anti-phishing
   ```

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License

Creative IT Institute
