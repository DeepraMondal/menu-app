# Menu App - Blockchain-Based Cryptographic Tool

A Python console application that integrates blockchain technology with cryptographic operations, including SHA-256 hashing, digital signatures using RSA, and a vehicle registration system. Each user action is recorded as an immutable block in the blockchain, demonstrating secure data management and verification.

## Features

- **SHA-256 Hash Generation**: Generate and store SHA-256 hashes for input messages.
- **Digital Signatures**: Create RSA key pairs, sign messages, and verify signatures using PSS padding.
- **Vehicle Registration System**: Register vehicles with details (number plate, owner, model) and retrieve information.
- **Blockchain Management**: View the entire blockchain, validate its integrity, and persist data to disk.
- **Interactive Menu**: User-friendly console interface for all operations.

## Requirements

- **Python**: Version 3.6 or higher (uses f-strings and modern syntax).
- **External Library**: `cryptography` (for RSA and digital signatures).

## Installation

1. **Clone the Repository**:
   ```bash
   git clone <repository-url>
   cd <repository-directory>
   ```

2. **Install Dependencies**:
   ```bash
   pip install cryptography
   ```

   This installs the `cryptography` library, which provides the necessary cryptographic primitives.

## Setup

- Ensure you have write permissions in the directory where the script runs, as the application saves files:
  - `blockchain.pkl`: Serialized blockchain data.
  - `private_key.pem` and `public_key.pem`: RSA key pair for digital signatures.
  - `signature.bin`: Binary signature file for verification.
- The blockchain starts with a genesis block if no existing `blockchain.pkl` is found.

## Usage

1. **Run the Application**:
   ```bash
   python menu_app.py
   ```

2. **Navigate the Menu**:
   - **1. Generate SHA-256 Hash**: Enter a message to compute its SHA-256 hash. The operation is added to the blockchain.
   - **2. Create and Verify Digital Signature**:
     - Create RSA keys (saved to files).
     - Sign a message using the private key.
     - Verify a signature using the public key.
   - **3. Vehicle Registration System**:
     - Register a vehicle with number plate, owner, and model.
     - Retrieve details by number plate.
   - **4. View Blockchain Data**: Display all blocks with their data and timestamps.
   - **5. Exit**: Quit the application.

3. **Example Interaction**:
   ```
   Menu:
   1. Generate SHA-256 Hash
   2. Create and Verify Digital Signature
   3. Vehicle Registration System
   4. View Blockchain Data
   5. Exit
   Enter your choice: 1
   Enter the message to hash: Hello World
   SHA-256 Hash: a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e49
   ```

## How It Works

### Blockchain Structure
- **Block Class**: Represents each block with index, previous hash, timestamp, data, and current hash.
- **Blockchain Class**: Manages the chain, including creation of the genesis block, adding new blocks, hash calculation, and validation.
- Each operation (hashing, signing, registration) creates a new block appended to the chain.

### Cryptographic Operations
- **Hashing**: Uses Python's `hashlib` for SHA-256.
- **Digital Signatures**: Employs RSA (2048-bit) with PSS padding via the `cryptography` library for secure signing and verification.
- Keys are generated, saved, and loaded from PEM files.

### Persistence
- The blockchain is saved/loaded using `pickle` for serialization.
- Ensures data integrity across sessions.

### Validation
- The `is_chain_valid` method checks hash consistency and previous hash links to detect tampering.

## Project Structure

- `menu_app.py`: Main script containing all classes, functions, and the menu loop.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your improvements.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Disclaimer

This is a demonstration application for educational purposes. It is not intended for production use without further security audits and enhancements.
