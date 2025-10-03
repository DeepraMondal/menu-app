# Import necessary modules
import hashlib  # For SHA-256 hashing
import os  # For file operations
import pickle  # For serializing the blockchain
import time  # For timestamps
#from cryptography.hazmat.primitives
import serialization, hashes  # For cryptographic operations
#from cryptography.hazmat.primitives.asymmetric 
import rsa, padding  # For RSA and PSS padding
#from cryptography.hazmat.backends 
import default_backend  # Default backend for cryptography

# Define the Block class to represent each block in the blockchain
class Block:
    def __init__(self, index, previous_hash, timestamp, data, hash):
        self.index = index  # Block index
        self.previous_hash = previous_hash  # Hash of the previous block
        self.timestamp = timestamp  # Timestamp of block creation
        self.data = data  # Data stored in the block
        self.hash = hash  # Hash of the current block

# Define the Blockchain class to manage the chain of blocks
class Blockchain:
    def __init__(self):
        self.load_chain()  # Load existing chain or create genesis

    def create_genesis_block(self):
        # Create the first block (genesis block)
        return Block(0, "0", time.time(), "Genesis Block", self.calculate_hash(0, "0", time.time(), "Genesis Block"))

    def get_latest_block(self):
        # Get the most recent block
        return self.chain[-1]

    def add_block(self, new_block):
        # Add a new block to the chain
        new_block.previous_hash = self.get_latest_block().hash
        new_block.hash = self.calculate_hash(new_block.index, new_block.previous_hash, new_block.timestamp, new_block.data)
        self.chain.append(new_block)
        self.save_chain()  # Persist the chain

    def calculate_hash(self, index, previous_hash, timestamp, data):
        # Calculate SHA-256 hash for a block
        value = str(index) + str(previous_hash) + str(timestamp) + str(data)
        return hashlib.sha256(value.encode()).hexdigest()

    def is_chain_valid(self):
        # Validate the integrity of the blockchain
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i-1]

            if current_block.hash != self.calculate_hash(current_block.index, current_block.previous_hash, current_block.timestamp, current_block.data):
                return False
            if current_block.previous_hash != previous_block.hash:
                return False
        return True

    def save_chain(self, filename='blockchain.pkl'):
        # Save the blockchain to a file
        with open(filename, 'wb') as f:
            pickle.dump(self.chain, f)

    def load_chain(self, filename='blockchain.pkl'):
        # Load the blockchain from a file or create genesis if not exists
        if os.path.exists(filename):
            with open(filename, 'rb') as f:
                self.chain = pickle.load(f)
        else:
            self.chain = [self.create_genesis_block()]

# Initialize the global blockchain instance
blockchain = Blockchain()

# Function to register a vehicle and add to blockchain
def register_vehicle(number_plate, owner, model):
    data = f"Operation: Vehicle Registration, Number Plate: {number_plate}, Owner: {owner}, Model: {model}"
    new_block = Block(len(blockchain.chain), "", time.time(), data, "")
    blockchain.add_block(new_block)
    print("Vehicle registered and block added to the blockchain.")

# Function to retrieve vehicle details from blockchain
def retrieve_vehicle_details(number_plate):
    for block in blockchain.chain:
        if number_plate in block.data:
            return block.data
    return "Vehicle not found"

# Function to generate SHA-256 hash
def generate_sha256_hash(message):
    return hashlib.sha256(message.encode()).hexdigest()

# Digital Signature Functions

# Generate RSA key pair
def create_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Save keys to files
def save_keys(private_key, public_key, private_filename, public_filename):
    with open(private_filename, "wb") as key_file:
        key_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    with open(public_filename, "wb") as key_file:
        key_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

# Load keys from files
def load_keys(private_filename, public_filename):
    with open(private_filename, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    with open(public_filename, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return private_key, public_key

# Create digital signature
def create_digital_signature(private_key, message):
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Verify digital signature
def verify_digital_signature(public_key, message, signature):
    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Verification failed: {e}")
        return False

# Main menu function
def main():
    while True:  # Loop until user chooses to exit
        print("\nMenu:")
        print("1. Generate SHA-256 Hash")
        print("2. Create and Verify Digital Signature")
        print("3. Vehicle Registration System")
        print("4. View Blockchain Data")
        print("5. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':  # Hash generation option
            message = input("Enter the message to hash: ")
            hash_result = generate_sha256_hash(message)
            data = f"Operation: Generate SHA-256 Hash, Message: {message}, Hash: {hash_result}"
            new_block = Block(len(blockchain.chain), "", time.time(), data, "")
            blockchain.add_block(new_block)
            print(f"SHA-256 Hash: {hash_result}")

        elif choice == '2':  # Digital signature submenu
            sub_choice = input("1. Create Keys\n2. Sign a Message\n3. Verify a Signature\nEnter your choice: ")
            if sub_choice == '1':  # Create keys
                private_key, public_key = create_keys()
                save_keys(private_key, public_key, 'private_key.pem', 'public_key.pem')
                data = "Operation: Digital Signature Keys Created"
                new_block = Block(len(blockchain.chain), "", time.time(), data, "")
                blockchain.add_block(new_block)
                print("Keys created and saved successfully.")
            elif sub_choice == '2':  # Sign message
                message = input("Enter the message to sign: ")
                private_key, _ = load_keys('private_key.pem', 'public_key.pem')
                signature = create_digital_signature(private_key, message)
                with open('signature.bin', 'wb') as sig_file:
                    sig_file.write(signature)
                data = f"Operation: Message Signed, Message: {message}"
                new_block = Block(len(blockchain.chain), "", time.time(), data, "")
                blockchain.add_block(new_block)
                print("Signature created and saved successfully.")
            elif sub_choice == '3':  # Verify signature
                message = input("Enter the message to verify: ")
                _, public_key = load_keys('private_key.pem', 'public_key.pem')
                with open('signature.bin', 'rb') as sig_file:
                    signature = sig_file.read()
                print(f"Message to verify: {message}")
                print(f"Signature: {signature}")
                is_valid = verify_digital_signature(public_key, message, signature)
                data = f"Operation: Signature Verification, Message: {message}, Result: {'Valid' if is_valid else 'Invalid'}"
                new_block = Block(len(blockchain.chain), "", time.time(), data, "")
                blockchain.add_block(new_block)
                if is_valid:
                    print("Signature is valid.")
                else:
                    print("Signature is invalid.")

        elif choice == '3':  # Vehicle registration submenu
            sub_choice = input("1. Register Vehicle\n2. Retrieve Vehicle Details\nEnter your choice: ")
            if sub_choice == '1':  # Register vehicle
                number_plate = input("Enter the number plate: ")
                owner = input("Enter the owner's name: ")
                model = input("Enter the model: ")
                register_vehicle(number_plate, owner, model)
            elif sub_choice == '2':  # Retrieve details
                number_plate = input("Enter the number plate to retrieve details: ")
                details = retrieve_vehicle_details(number_plate)
                print(details)

        elif choice == '4':  # View blockchain data
            print("Blockchain Data:")
            for block in blockchain.chain:
                print(f"Block {block.index}: {block.data} (Timestamp: {time.ctime(block.timestamp)})")

        elif choice == '5':  # Exit
            print("Exiting the program.")
            break

        else:  # Invalid choice
            print("Invalid choice. Please try again.")

# Run the main function if script is executed directly
if __name__ == "__main__":
    main()