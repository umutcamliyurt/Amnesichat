
let imageData = "";  // Declare a global variable to store image data
// Consolidate all actions that should happen when the page loads
window.onload = async function() {
    populateFormWithStoredCredentials();
    const password = document.getElementById('password').value;
    refreshMessages(password); // Load messages using the stored password
    loadstoredFingerprints(); // Load stored recipient fingerprints
};

// Define allowed tags and attributes in DOMPurify config
const purifyConfig = {
    ALLOWED_TAGS: ['strong', 'em', 'u', 'a'],
    ALLOWED_ATTR: [
        'id', 'for', 'type', 'name', 'required', 'onclick', 'onchange', 'style', 'value', 'class'
    ]
};

// Define the function to format and sanitize messages
function formatAndSanitizeMessages(html) {
// Use DOMPurify to sanitize the message content based on allowed tags and attributes
const sanitizedContent = DOMPurify.sanitize(html, purifyConfig);

// Only create a <p> tag if content is non-empty
return sanitizedContent.trim() ? `<p><strong>${sanitizedContent}</strong></p>` : '';
}

async function refreshMessages(roomPassword) {
    fetch(`/messages?password=${encodeURIComponent(roomPassword)}`)
        .then(response => response.text())
        .then(html => {
            // Load raw messages into a different container
            const rawMessagesContainer = document.getElementById('raw_messages');
            rawMessagesContainer.innerHTML = ''; // Clear existing raw messages

            // Use formatAndSanitizeMessages to sanitize and format HTML
            const sanitizedHtml = formatAndSanitizeMessages(html);

            // Insert sanitized and formatted content into the raw_messages container
            rawMessagesContainer.innerHTML = sanitizedHtml;

            // Process and decrypt messages
            decryptMessages();
        })
        .catch(error => {
            console.error('Error fetching messages:', error);
        });
}

async function decryptMessages() {
    const rawMessagesContainer = document.getElementById('raw_messages');
    const sanitizedContent = DOMPurify.sanitize(rawMessagesContainer.innerHTML);

    if (sanitizedContent !== rawMessagesContainer.innerHTML) {
        console.log("Potential XSS attack prevented.");
        rawMessagesContainer.innerHTML = "XSS Attack prevented!";
        return;
    }

    const pgpMessageRegex = /-----BEGIN PGP MESSAGE-----(.*?)-----END PGP MESSAGE-----/gs;
    const pgpKeyRegex = /-----BEGIN PGP PUBLIC KEY BLOCK-----(.*?)-----END PGP PUBLIC KEY BLOCK-----/gs;
    const encryptedMessages = sanitizedContent.match(pgpMessageRegex);
    const extractedKeys = sanitizedContent.match(pgpKeyRegex);

    const messagesContainer = document.getElementById('messages');
    messagesContainer.innerHTML = ''; // Clear the messages container before processing

    if (!encryptedMessages && !extractedKeys) {
        console.log("No encrypted messages or PGP keys found.");
        return;
    }

    const privateKeyArmored = localStorage.getItem('pgp-private-key');
    if (!privateKeyArmored) {
        console.error("Private key not found in localStorage.");
        return;
    }

    const passphrase = document.getElementById('passphrase').value;
    if (!passphrase) {
        console.error("Passphrase is required.");
        return;
    }

    try {
        const privateKey = await openpgp.decryptKey({
            privateKey: await openpgp.readPrivateKey({ armoredKey: privateKeyArmored }),
            passphrase: passphrase
        });

        // Process encrypted PGP messages
        if (encryptedMessages) {
            console.log("Found encrypted messages. Starting decryption...");
            for (let i = 0; i < encryptedMessages.length; i++) {
                const encryptedMessage = encryptedMessages[i];
                try {
                    // Decrypt the PGP message
                    const message = await openpgp.readMessage({ armoredMessage: encryptedMessage });
                    const { data: decrypted } = await openpgp.decrypt({
                        message,
                        decryptionKeys: privateKey
                    });

                    if (!decrypted) {
                        throw new Error("Decryption returned empty or invalid data.");
                    }

                    // Log the decrypted message for debugging
                    console.log(`Decrypted message #${i + 1}:`, decrypted);

                    // Sanitize the decrypted content before inserting it into the page
                    const sanitizedDecryptedMessage = DOMPurify.sanitize(decrypted);

                    // Check if image data exists in the decrypted message
                    const imageDataMatch = sanitizedDecryptedMessage.match(/IMAGEDATA:(.*)/);
                    if (imageDataMatch) {
                        let imageBase64 = imageDataMatch[1];

                        // Ensure only valid Base64 data is used (before any potential metadata)
                        const base64ImageMatch = imageBase64.match(/^([A-Za-z0-9+/=]+)$/);
                        if (base64ImageMatch) {
                            // Create the image element with required attributes
                            const imageElement = document.createElement('img');
                            imageElement.src = `data:image/png;base64,${base64ImageMatch[1]}`;
                            imageElement.alt = "Image";
                            imageElement.style.maxWidth = '100%';
                            imageElement.style.height = 'auto';

                            // Append the image to the messages container
                            messagesContainer.appendChild(imageElement);

                            // Extract and display any metadata following the image
                            const metadata = sanitizedDecryptedMessage.replace(imageDataMatch[0], '').trim();
                            if (metadata) {
                                // Sanitize and allow HTML rendering for metadata
                                const metadataParagraph = document.createElement('p');
                                metadataParagraph.innerHTML = DOMPurify.sanitize(metadata, { ALLOWED_TAGS: ['strong', 'em', 'u', 'a'] }); // Allow some tags like <strong>, <em>, etc.
                                messagesContainer.appendChild(metadataParagraph);
                            }
                        } else {
                            console.warn("Invalid Base64 image data.");
                        }
                    } else {
                        // Create the message without username and timestamp
                        const messageWithoutMeta = `<p>${sanitizedDecryptedMessage}</p>`;
                        messagesContainer.innerHTML += messageWithoutMeta;
                    }

                    console.log(`Decrypted message #${i + 1}:`, sanitizedDecryptedMessage);
                } catch (error) {
                    console.error(`Error during message #${i + 1} decryption:`, error.message);
                    continue; // Skip this message and continue processing others
                }
            }
        }
        
// Check if PGP public key exists in local storage
const userPublicKey = localStorage.getItem('pgp-public-key');

// Process extracted PGP public key blocks
if (extractedKeys) {
    console.log("Found PGP public key blocks. Processing...");
    const hiddenKeys = JSON.parse(localStorage.getItem('hiddenKeys')) || [];
    const processedKeys = new Set(); // Track already processed keys during this run

    let userPublicKeyFingerprint = null;
    if (userPublicKey) {
        try {
            const userKey = await openpgp.readKey({ armoredKey: userPublicKey });
            userPublicKeyFingerprint = userKey.getFingerprint();
        } catch (error) {
            console.error("Error importing user public key:", error.message);
        }
    }

    for (const keyBlock of extractedKeys) {
        try {
            const key = await openpgp.readKey({ armoredKey: keyBlock });
            const keyFingerprint = key.getFingerprint().toLowerCase(); // Convert to lowercase for consistency

            // Check if this key is already processed or hidden, if so skip it
            if (processedKeys.has(keyFingerprint) || hiddenKeys.includes(keyFingerprint) || keyFingerprint === userPublicKeyFingerprint.toLowerCase()) {
                console.log(`Skipping key with fingerprint: ${keyFingerprint} (already processed or hidden)`);
                continue;
            }

            // Mark the key as processed for the current run
            processedKeys.add(keyFingerprint);

            const keyBlockDiv = document.createElement('div');
            keyBlockDiv.className = 'pgp-key-block';

            const keyInfo = document.createElement('p');
            keyInfo.textContent = `Found Public Key Block - GPG Fingerprint: ${keyFingerprint}`;

            const importButton = document.createElement('button');
            importButton.textContent = 'Import Key';
            importButton.onclick = () => {
                importKey(keyBlock);
                hideKeyBlock(keyFingerprint, keyBlockDiv);
            };

            const rejectButton = document.createElement('button');
            rejectButton.textContent = 'Reject Key';
            rejectButton.onclick = () => {
                rejectKey(keyBlock);
                hideKeyBlock(keyFingerprint, keyBlockDiv);
            };

            keyBlockDiv.appendChild(keyInfo);
            keyBlockDiv.appendChild(importButton);
            keyBlockDiv.appendChild(rejectButton);

            messagesContainer.appendChild(keyBlockDiv);
        } catch (error) {
            console.error("Error importing key block:", error.message);
        }
    }

    function hideKeyBlock(fingerprint, blockDiv) {
        blockDiv.style.display = 'none';
        hiddenKeys.push(fingerprint);
        localStorage.setItem('hiddenKeys', JSON.stringify(hiddenKeys));
    }
}

} catch (error) {
    console.error("Error unlocking private key:", error.message);
    alert("Failed to unlock private key. Please check the passphrase.");
}

// Hide empty paragraphs
messagesContainer.querySelectorAll('p').forEach((p) => {
    if (!p.textContent.trim()) {
        p.style.display = 'none';
    }
});
}


// Function to import a public key
async function importKey(keyBlock) {
    // Retrieve existing public keys and fingerprints from localStorage
    let storedKeys = JSON.parse(localStorage.getItem('recipient-public-keys')) || [];
    let storedFingerprints = JSON.parse(localStorage.getItem('public-key-fingerprints')) || [];

    try {
        // Import the key block using OpenPGP.js
        const key = await openpgp.readKey({ armoredKey: keyBlock });

        // Get the fingerprint of the public key
        const keyFingerprint = key.getFingerprint();

        // Check if the key is already imported by comparing the fingerprint
        if (!storedFingerprints.includes(keyFingerprint)) {
            // Add the new key to the stored keys list
            storedKeys.push(keyBlock);

            // Store the fingerprint (instead of the SHA-512 fingerprint)
            storedFingerprints.push({ keyBlock, fingerprint: keyFingerprint });

            // Update localStorage with the new key and fingerprint
            localStorage.setItem('recipient-public-keys', JSON.stringify(storedKeys));
            localStorage.setItem('public-key-fingerprints', JSON.stringify(storedFingerprints));

            // Provide feedback to the user
            console.log(`Public key imported: ${keyFingerprint}`);
        } else {
            console.log('Key is already imported.');
        }
    } catch (error) {
        console.error('Error importing key:', error.message);
    }
}

// Function to reject a public key
async function rejectKey(keyBlock) {
    // Retrieve existing public keys and fingerprints from localStorage
    let storedKeys = JSON.parse(localStorage.getItem('recipient-public-keys')) || [];
    let storedFingerprints = JSON.parse(localStorage.getItem('public-key-fingerprints')) || [];

    try {
        // Import the key block using OpenPGP.js to get its fingerprint
        const key = await openpgp.readKey({ armoredKey: keyBlock });
        const keyFingerprint = key.getFingerprint();

        // Find the index of the key's fingerprint to remove
        const keyIndex = storedFingerprints.findIndex(item => item.fingerprint === keyFingerprint);
        if (keyIndex !== -1) {
            // Remove the key from the stored list
            storedKeys.splice(keyIndex, 1);

            // Remove the corresponding fingerprint
            storedFingerprints.splice(keyIndex, 1);

            // Update localStorage with the modified list of keys and fingerprints
            localStorage.setItem('recipient-public-keys', JSON.stringify(storedKeys));
            localStorage.setItem('public-key-fingerprints', JSON.stringify(storedFingerprints));

            // Provide feedback to the user
            console.log('Public key rejected.');
        } else {
            console.log('Key not found for rejection.');
        }
    } catch (error) {
        console.error('Error rejecting key:', error.message);
    }
}

    // Function to load private key
    async function loadPrivateKey(event) {
        const file = event.target.files[0];
        if (!file) {
            alert("Please select a private key file.");
            return;
        }

        const reader = new FileReader();
        reader.onload = async function(e) {
            const privateKeyArmored = e.target.result;
            try {
                const privateKey = await openpgp.readPrivateKey({ armoredKey: privateKeyArmored });
                console.log("Private key loaded successfully.");
                localStorage.setItem('pgp-private-key', privateKeyArmored);
                alert("Private key loaded successfully!");
            } catch (error) {
                alert("Failed to load private key: " + error.message);
            }
        };
        reader.readAsText(file);
    }

    async function generatePGPKey() {
        const passphrase = prompt("Enter a passphrase to protect your private key:");
    
        if (!passphrase) {
            alert("Passphrase is required!");
            return;
        }
    
        try {
            // Key generation options (for ECC/Ed25519)
            const options = {
                type: 'ecc', // ECC (Elliptic Curve Cryptography)
                curve: 'curve25519', // Curve name, defaults to curve25519
                userIDs: [{ name: 'Anonymous', email: 'anon@example.com' }], // Identity info
                passphrase: passphrase, // Passphrase to protect the private key
                format: 'armored' // Output format (armored)
            };
    
            // Generate the key pair
            const { privateKey, publicKey, revocationCertificate } = await openpgp.generateKey(options);
    
            // Store the private and public keys
            localStorage.setItem('pgp-private-key', privateKey);
            localStorage.setItem('pgp-public-key', publicKey);
    
            // Import the public key to get the fingerprint
            const publicKeyObj = await openpgp.readKey({ armoredKey: publicKey });
            const publicKeyFingerprint = publicKeyObj.getFingerprint(); // GPG fingerprint
    
            // Load stored fingerprints from localStorage or initialize an empty array
            const storedFingerprints = JSON.parse(localStorage.getItem('public-key-fingerprints')) || [];
    
            // Add the new public key's fingerprint to the stored fingerprints array
            storedFingerprints.push({
                fileName: 'Your Public Key',
                fingerprint: publicKeyFingerprint
            });
    
            // Store the updated list of fingerprints back into localStorage
            localStorage.setItem('public-key-fingerprints', JSON.stringify(storedFingerprints));
    
            // Display success and log keys
            alert("PGP key pair generated and stored successfully!");
            console.log("Private Key:", privateKey);
            console.log("Public Key:", publicKey);
            console.log("Revocation Certificate:", revocationCertificate);
    
            // Call loadstoredFingerprints to update the UI with the new fingerprint
            loadstoredFingerprints();
    
        } catch (error) {
            console.error("Error generating PGP key:", error);
            alert("Failed to generate PGP key.");
        }
    }    

async function downloadPGPKey() {
    const publicKey = localStorage.getItem('pgp-public-key');
    if (!publicKey) {
        alert("No PGP public key found in localStorage.");
        return;
    }

    // Create a Blob with the public key to trigger download
    const blob = new Blob([publicKey], { type: 'application/pgp-keys' });
    const link = document.createElement('a');
    const username = document.getElementById("username").value;
    link.href = URL.createObjectURL(blob);
    link.download = `${(username)}"publicKey.asc`;
    link.click();
}

async function downloadPrivateKey() {
    const privateKey = localStorage.getItem('pgp-private-key');
    if (!privateKey) {
        alert("No private key found in localStorage.");
        return;
    }

    // Create a Blob with the private key to trigger download
    const blob = new Blob([privateKey], { type: 'application/pgp-keys' });

    // Create a link element to trigger the download
    const link = document.createElement('a');
    
    // Get the username from the form, or fall back to a default if not available
    const username = document.getElementById("username").value || 'anonymous';
    
    // Set up the download link with a filename that includes the username
    link.href = URL.createObjectURL(blob);
    link.download = `${username}_privateKey.asc`; // Use the username in the filename
    link.click(); // Simulate a click to trigger the download
}


// Function to save keys as a backup
async function saveBackup() {
const privateKey = localStorage.getItem('pgp-private-key');
const publicKey = localStorage.getItem('pgp-public-key');
const recipientKeys = localStorage.getItem('recipient-public-keys');
const publicKeyfingerprints = localStorage.getItem('public-key-fingerprints');
const username = document.getElementById('username').value; // Get the username

if (!privateKey || !publicKey) {
    alert("Private and public keys are required to create a backup.");
    return;
}

const backupData = {
    privateKey,
    publicKey,
    recipientKeys: recipientKeys || '[]',
    publicKeyfingerprints: publicKeyfingerprints || '[]',
    username: username || '', // Include the username in the backup
};

const blob = new Blob([JSON.stringify(backupData)], { type: 'application/json' });
const link = document.createElement('a');
link.href = URL.createObjectURL(blob);
link.download = username + '_pgp_key_backup.json';
link.click();
alert("Backup saved successfully!");
}


// Function to load keys from a backup file
async function loadBackup(event) {
const fileInput = document.createElement('input');
fileInput.type = 'file';
fileInput.accept = 'application/json';

fileInput.onchange = async (event) => {
    const file = event.target.files[0];
    if (!file) {
        alert("Please select a backup file.");
        return;
    }

    const reader = new FileReader();
    reader.onload = function (e) {
        try {
            const backupData = JSON.parse(e.target.result);
            if (!backupData.privateKey || !backupData.publicKey) {
                throw new Error("Invalid backup file. Missing keys.");
            }

            // Restore keys and fingerprints to localStorage
            localStorage.setItem('pgp-private-key', backupData.privateKey);
            localStorage.setItem('pgp-public-key', backupData.publicKey);
            if (backupData.recipientKeys) {
                localStorage.setItem('recipient-public-keys', backupData.recipientKeys);
            }
            if (backupData.publicKeyfingerprints) {
                localStorage.setItem('public-key-fingerprints', backupData.publicKeyfingerprints);
            }

            // Restore the username and password fields
            document.getElementById('username').value = backupData.username || ''; // Restore username

            alert("Backup loaded successfully!");
            // Optionally refresh the UI to reflect loaded keys/fingerprints
            loadstoredFingerprints();
        } catch (error) {
            alert("Failed to load backup: " + error.message);
        }
    };

    reader.readAsText(file);
};

// Trigger the file input dialog
fileInput.click();
}

document.addEventListener("DOMContentLoaded", function() {
const sendMessageButton = document.getElementById('send-message-button');
sendMessageButton.disabled = true; // Initially disabled

// Retrieve the checkbox state from localStorage and update the checkbox and button state
const tosChecked = localStorage.getItem('tos-checked') === 'true';
const tosCheckbox = document.getElementById('tos-checkbox');
const termsLink = document.getElementById('terms-link');

tosCheckbox.checked = tosChecked; // Set the checkbox state
if (tosChecked) {
    sendMessageButton.disabled = false; // Enable the button if checkbox is checked
    termsLink.style.color = 'skyblue'; // Change the color of the link
} else {
    sendMessageButton.disabled = true; // Keep the button disabled if checkbox is unchecked
    termsLink.style.color = '#ff000d'; // Default link color
}
const fileInput = document.getElementById('fileInput');
if (fileInput) {
    fileInput.addEventListener('change', loadPublicKeys);
}
});

function loadstoredFingerprints() {
    const storedfingerprints = JSON.parse(localStorage.getItem('public-key-fingerprints')) || [];
    const publicKeyContainer = document.getElementById('public-key-fingerprints');

    if (!publicKeyContainer) {
        console.error('publicKeyContainer is null. Retry loading after DOM is ready.');
        return; // Stop execution if the container is not available
    }

    publicKeyContainer.innerHTML = 'Imported Public Keys:\n'; // Clear previous content

    // Display each entry's fileName and fingerprint with a remove button
    storedfingerprints.forEach((entry, index) => {
        const fileName = entry.fileName || "(imported from chat)"; // Fallback if fileName is not provided
        const fingerprint = entry.fingerprint; // Extract the fingerprint property
        if (!fingerprint) return; // Skip if there's no fingerprint

        const itemDiv = document.createElement('div');
        itemDiv.className = 'fingerprint-item';

        // Add fileName and fingerprint as text
        const textDiv = document.createElement('div');
        textDiv.className = 'fingerprint-text';
        textDiv.textContent = `${fileName}: [GPG Fingerprint] ${fingerprint}`;

        // Add the remove button
        const removeButton = document.createElement('button');
        removeButton.textContent = 'X';
        removeButton.className = 'remove-button';
        removeButton.onclick = () => removeSpecificPublicKey(index);

        // Append text and button to the container
        itemDiv.appendChild(textDiv);
        itemDiv.appendChild(removeButton);
        publicKeyContainer.appendChild(itemDiv);
    });
}


// Remove a specific public key and its fingerprint
function removeSpecificPublicKey(index) {
    const storedfingerprints = JSON.parse(localStorage.getItem('public-key-fingerprints')) || [];
    const recipientPublicKeys = JSON.parse(localStorage.getItem('recipient-public-keys')) || [];

    if (index < 0 || index >= storedfingerprints.length) {
        alert('Invalid index!');
        return;
    }

    // Remove the specific fingerprint and public key
    storedfingerprints.splice(index, 1);
    recipientPublicKeys.splice(index, 1);

    // Update localStorage
    localStorage.setItem('public-key-fingerprints', JSON.stringify(storedfingerprints));
    localStorage.setItem('recipient-public-keys', JSON.stringify(recipientPublicKeys));

    // Reload the displayed fingerprints
    loadstoredFingerprints();
}

// Clear all loaded public keys and fingerprints
function clearAllPublicKeys() {
    const publicKeyContainer = document.getElementById('public-key-fingerprints');
    publicKeyContainer.innerHTML = '';

    localStorage.removeItem('recipient-public-keys');
    localStorage.removeItem('public-key-fingerprints');

    alert('All loaded public keys and fingerprints have been cleared!');
}

// Create a Set to keep track of already displayed fingerprints to avoid duplicates
const displayedFingerprints = new Set();

storedfingerprints.forEach(item => {
    // Check if the fingerprint has already been displayed
    if (!displayedFingerprints.has(item.fingerprint)) {
        const fingerprintElement = document.createElement('p');
        fingerprintElement.innerText = `Encrypting for: ${item.fileName} - GPG Fingerprint: ${item.fingerprint}`;
        fingerprintElement.classList.add('small-fingerprint-label');
        publicKeyContainer.appendChild(fingerprintElement);

        // Add the fingerprint to the Set to track it
        displayedFingerprints.add(item.fingerprint);
    }
});

// Function to load a user's public key and store its fingerprint
async function loadUserPublicKey(event) {
    const file = event.target.files[0];
    if (!file) {
        alert("Please select a public key file.");
        return;
    }

    const reader = new FileReader();
    reader.onload = async function(e) {
        const publicKeyArmored = e.target.result;
        try {
            // Read the public key using OpenPGP.js
            const publicKey = await openpgp.readKey({ armoredKey: publicKeyArmored });
            console.log("User's public key loaded successfully.");

            // Store the user's public key in localStorage
            localStorage.setItem('pgp-public-key', publicKeyArmored);

            // Get the fingerprint of the public key
            const fingerprint = publicKey.getFingerprint();

            // Retrieve and update the stored fingerprints in localStorage
            let storedFingerprints = JSON.parse(localStorage.getItem('public-key-fingerprints')) || [];
            const userFingerprintEntry = { fileName: 'your public key', fingerprint: fingerprint };

            // Check if the user's public key fingerprint is already stored
            const existingUserFingerprint = storedFingerprints.find(entry => entry.fileName === 'your public key');
            if (existingUserFingerprint) {
                // Update existing entry
                existingUserFingerprint.fingerprint = fingerprint;
            } else {
                // Add new entry
                storedFingerprints.push(userFingerprintEntry);
            }

            // Save the updated fingerprints back to localStorage
            localStorage.setItem('public-key-fingerprints', JSON.stringify(storedFingerprints));

            // Display the user's public key fingerprint on the page
            const publicKeyFingerprintContainer = document.getElementById('public-key-fingerprints');
            const userPublicKeyFingerprintElement = document.createElement('p');
            userPublicKeyFingerprintElement.innerText = `Your public key - GPG Fingerprint: ${fingerprint}`;
            userPublicKeyFingerprintElement.classList.add('user-public-key-fingerprint');
            publicKeyFingerprintContainer.appendChild(userPublicKeyFingerprintElement);

            alert("Your public key loaded successfully!");
        } catch (error) {
            alert("Failed to load your public key: " + error.message);
        }
    };
    reader.readAsText(file);
}

async function encryptMessage(event) {
    event.preventDefault();

    const username = "<strong>" + document.getElementById("username").value + "</strong>" + ": ";

    // Retrieve the recipient public keys from localStorage
    const recipientPublicKeys = JSON.parse(localStorage.getItem('recipient-public-keys') || '[]');

    // Get the sender's public key
    const senderPublicKeyArmored = localStorage.getItem('pgp-public-key');
    if (!senderPublicKeyArmored) {
        alert("Sender's public key must be loaded.");
        return;
    }

    // Prepare the sender's public key data to send
    const dataForPublicKey = {
        message: senderPublicKeyArmored,  // Sending the sender's public key
        password: document.getElementById("password").value
    };

    try {
        const responseForPublicKey = await fetch(`${window.location.origin}/send`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(dataForPublicKey)
        });

        if (!responseForPublicKey.ok) {
            const errorMessage = await responseForPublicKey.text();
            alert(`Failed to send sender's public key: ${errorMessage}`);
            return;  // Exit the function if sending the public key fails
        }
        console.log("Sender's public key sent successfully.");
    } catch (error) {
        console.error("Error sending sender's public key:", error);
        alert("Failed to send sender's public key.");
        return;
    }

    // Check if message passphrase is provided
    const passphrase = document.getElementById('passphrase').value;
    if (!passphrase) {
        alert("Please provide a passphrase to unlock your private key.");
        return;
    }

    // Retrieve the message text and prepare the complete message
    const textMessage = username + document.getElementById("message").value;
    const completeMessage = imageData ? `${imageData}\n${textMessage}` : textMessage;  // Include image data if available

    try {
        // If recipient public keys are found, we encrypt for recipients as well
        const senderKey = await openpgp.readKey({ armoredKey: senderPublicKeyArmored });
        const recipientKeys = recipientPublicKeys.length > 0
            ? await Promise.all(recipientPublicKeys.map(keyArmored => openpgp.readKey({ armoredKey: keyArmored })))
            : [];

        // Create the message object to encrypt
        const msg = await openpgp.createMessage({ text: completeMessage });

        // Retrieve the sender's private key for signing
        const privateKeyArmored = localStorage.getItem('pgp-private-key');
        const privateKey = await openpgp.decryptKey({
            privateKey: await openpgp.readPrivateKey({ armoredKey: privateKeyArmored }),
            passphrase: passphrase
        });

        // Encrypt the message with the public key(s) and sign with sender's private key
        const encryptedMessage = await openpgp.encrypt({
            message: msg,
            encryptionKeys: [senderKey, ...recipientKeys],
            signingKeys: privateKey
        });

        // Prepare the encrypted message data to send
        const dataForMessage = {
            message: encryptedMessage,
            password: document.getElementById("password").value
        };

        // Send the encrypted message
        const responseForMessage = await fetch(`${window.location.origin}/send`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(dataForMessage)
        });

        if (responseForMessage.ok) {
            window.location.href = `/`;  // Redirect after sending
        } else {
            const errorMessage = await responseForMessage.text();
            alert(`Failed to send message: ${errorMessage}`);
        }

    } catch (error) {
        console.error("Error encrypting message:", error);
        alert("Failed to encrypt message.");
    }
}

// Handle the image upload
async function handleImageUpload(event) {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = function (e) {
        imageData = `IMAGEDATA:${e.target.result.split(",")[1]}`;  // Store Base64 string without the prefix
    };
    reader.readAsDataURL(file);
}

async function loadMessages() {
    // Get password value from input field
    const password = document.getElementById("password").value;

    // Build query string based on whether password is provided
    const queryString = password ? `?password=${encodeURIComponent(password)}` : '';

    // Fetch messages from the backend
    try {
        const response = await fetch(`/messages${queryString}`);
        if (response.ok) {
            const html = await response.text();
            document.getElementById("messages").innerHTML = html;
            decryptMessages();
        } else {
            document.getElementById("messages").innerHTML = "Failed to load messages.";
        }
    } catch (error) {
        console.error("Error loading messages:", error);
        document.getElementById("messages").innerHTML = "Error loading messages.";
    }
}

// Automatically load messages every 60 seconds
setInterval(loadMessages, 60000);

// Function to toggle the visibility of the advanced form fields
function toggleAdditionalFields() {
var x = document.getElementById("advanced-options");
if (x.style.display === "none") {
    x.style.display = "block";  // Show the advanced options
} else {
    x.style.display = "none";   // Hide the advanced options
}
}

// Function to show the help popup
function showHelp() {
document.getElementById('help-popup').style.display = 'block';
}

// Function to close the help popup
function closeHelp() {
document.getElementById('help-popup').style.display = 'none';
}