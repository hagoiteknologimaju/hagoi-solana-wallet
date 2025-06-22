# Hagoi-Solana-Wallet

Professional desktop wallet application for managing Solana (SOL) cryptocurrency. Built with Python and featuring a modern GUI interface powered by CustomTkinter.

## Features

- **Password-Protected Wallets**: Encrypted using PBKDF2-HMAC with SHA256
- **Mnemonic Phrase Support**: Generate and import wallets using 24-word seed phrases
- **Balance Tracking**: Real-time SOL balance display with USD conversion
- **SOL Transfers**: Send SOL to any Solana address with fee calculation
- **Transaction History**: Local storage and display of transaction records
- **Price Charts**: Real-time SOL price tracking and charts
- **QR Code Generation**: Generate QR codes for receiving payments
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

## Usage

### First Time Setup
1. **Create New Wallet**: Choose between creating with mnemonic phrase or Hagoi method
2. **Set Password**: Secure your wallet with a strong password
3. **Save Wallet File**: Choose location to save your encrypted wallet file

### Using the Wallet
1. **Check Balance**: SOL balance and USD equivalent displayed on main screen
2. **Send SOL**: Click "Transfer" to send SOL to another address
3. **Receive SOL**: Click "Receive SOL" to generate QR code for your address
4. **View History**: Transaction history automatically saved and displayed

## Security Best Practices

1. **Strong Passwords**: Use complex passwords for wallet encryption
2. **Backup Mnemonic**: Always backup your mnemonic phrase offline
3. **Secure Storage**: Store wallet files in secure locations

## About

Hagoi-Solana-Wallet is developed by Hagoi Teknologi Maju to provide secure and user-friendly access to the Solana blockchain.
