# Hagoi-Solana-Wallet

Professional desktop wallet application for managing Solana (SOL) cryptocurrency. Built with Python and featuring a modern GUI interface powered by CustomTkinter.

## Features

### Security
- **Password-Protected Wallets**: All wallets are encrypted using PBKDF2-HMAC with SHA256
- **Mnemonic Phrase Support**: Generate and import wallets using 24-word seed phrases
- **Private Key Management**: Secure private key storage and handling
- **Thread-Safe Operations**: Multi-threaded design with proper locking mechanisms

### Wallet Management
- **Create New Wallets**: Generate new Solana wallets with optional mnemonic phrases
- **Import Existing Wallets**: Support for importing from files, private keys, or mnemonic phrases
- **Balance Tracking**: Real-time SOL balance display with USD conversion
- **Transaction History**: Local storage and display of transaction records

### Trading & Transfers
- **SOL Transfers**: Send SOL to any Solana address
- **Network Support**: Works with both Mainnet and Devnet
- **Transaction Validation**: Input validation and error handling
- **Fee Calculation**: Automatic transaction fee handling

### Additional Features
- **Price Charts**: Real-time SOL price tracking and charts
- **QR Code Generation**: Generate QR codes for receiving payments
- **Modern UI**: Dark theme with neon green accents
- **Cross-Platform**: Works on Windows, macOS, and Linux

## Setup Instructions

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Installation

1. Install Python dependencies
```bash
pip install -r requirements.txt
```

2. Run application
```bash
python solana_wallet.py
```

### Required Packages
```
solana>=0.30.0
customtkinter>=5.2.0
cryptography>=41.0.0
matplotlib>=3.7.0
Pillow>=10.0.0
qrcode>=7.4.0
mnemonic>=0.20
```

## Usage

### Running the Application
```bash
python solana_wallet.py
```

### First Time Setup
1. **Create New Wallet**: Choose between creating with mnemonic phrase or Hagoi method
2. **Set Password**: Secure your wallet with a strong password
3. **Save Wallet File**: Choose location to save your encrypted wallet file
4. **Backup**: Write down your mnemonic phrase (if used) and store it safely

### Using the Wallet
1. **Check Balance**: Your SOL balance and USD equivalent are displayed on the main screen
2. **Send SOL**: Click "Transfer" to send SOL to another address
3. **Receive SOL**: Click "Receive SOL" to generate a QR code for your address
4. **View History**: Transaction history is automatically saved and displayed
5. **Price Charts**: Click "Price Chart" to view real-time SOL price data

### Import Existing Wallet
Choose from three import methods:
- **From Hagoi File**: Import encrypted .hagoi wallet files
- **From Private Key**: Import using base58-encoded private key
- **From Mnemonic**: Import using 12 or 24-word seed phrase

## Configuration

### Network Selection
The wallet defaults to Solana Mainnet. To use Devnet for testing:
```python
self.wallet = SolanaWallet(network="devnet")
```

### File Locations
- **Default Wallet**: `~/.solana_default_wallet.hagoi`
- **Transaction History**: `~/.solana_wallet_history/`
- **Wallet Files**: User-specified locations with `.hagoi` extension

## Security Best Practices

1. **Strong Passwords**: Use complex passwords for wallet encryption
2. **Backup Mnemonic**: Always backup your mnemonic phrase offline
3. **Secure Storage**: Store wallet files in secure locations
4. **Regular Backups**: Create multiple backups of important wallets
5. **Network Awareness**: Be cautious when switching between Mainnet and Devnet

## Development

### Project Structure
```
hagoi-solana-wallet/
├── solana_wallet.py          # Main application file
├── devnet.py                 # Development/testing utilities
├── requirements.txt          # Python dependencies
├── icons/                    # UI icons and graphics
│   ├── logo.ico
│   ├── wallet.png
│   ├── send.png
│   └── ...
├── background/               # Background images
└── output/                   # Build outputs
```

### Key Classes
- **`SolanaWallet`**: Core wallet functionality and Solana blockchain interaction
- **`SolanaWalletGUI`**: User interface and event handling
- **`WalletEncryption`**: Cryptographic operations for wallet security

### Building Executable
The project includes PyInstaller configuration for creating standalone executables:
```bash
pyinstaller --onefile --windowed solana_wallet.py
```

## API Reference

### SolanaWallet Class
```python
# Create new wallet
wallet_data = wallet.create_wallet()

# Get balance
balance = wallet.get_balance(public_key)

# Send transaction
signature = wallet.send_transaction(private_key, recipient, amount)

# Generate mnemonic
mnemonic = wallet.generate_mnemonic()

# Import from mnemonic
wallet_data = wallet.import_from_mnemonic(mnemonic)
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This software is provided "as is" without warranty of any kind. Users are responsible for:
- Securing their private keys and mnemonic phrases
- Understanding the risks of cryptocurrency transactions
- Compliance with local laws and regulations
- Testing on Devnet before using on Mainnet

## About

Hagoi-Solana-Wallet is developed by Hagoi Teknologi Maju to provide secure and user-friendly access to the Solana blockchain. Our mission is to make cryptocurrency management accessible and secure for everyone through innovative desktop solutions.
