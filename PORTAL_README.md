# Protecting College E-Mail — Faculty and Student Portals

This Streamlit project provides separate Faculty and Student portal pages. Faculty can send a confidential message and/or file to a registered student URN. Students sign in and can decrypt only messages addressed to their URN and encrypted to their own account key.

## Run locally

From this folder, install the listed dependencies if needed, then run:

```powershell
.\.venv\Scripts\Activate.ps1
streamlit run app.py
```

Open the local address printed by Streamlit. Use the Faculty Portal and Student Portal links in the sidebar or home page. Create a faculty account in the faculty page and a student account in the student page. Faculty can send to a student after that student account exists.

## Security behavior

- A student signup creates a 3072-bit RSA key pair. The public key is used to wrap a fresh per-message AES-256-GCM key. The student's private key is encrypted at rest using a key derived from the account password.
- Faculty content, subject, recipient details, and attachments are signed with the faculty RSA-PSS key and encrypted as one payload.
- A student's envelope URN is compared with the signed-in account URN before decryption. The signed payload URN is checked again after signature verification and before rendering content or enabling file download.
- Passwords are stored as salted PBKDF2-HMAC-SHA256 hashes. Mailbox records contain JSON envelopes with encrypted content, not plaintext message bodies or files.

## Prototype limits

This is an educational local prototype. Signup is open and does not prove that a user is college faculty or owns the URN entered. A production deployment must provision and verify identities through the college, protect the database and faculty signing key, use HTTPS and secure backups, and define a private-key recovery process. A student who forgets their password cannot decrypt their stored private key without the original password. Do not use this demo for real sensitive records.

The original single-user cryptography functions remain usable for the included basic crypto demonstration; portal mail uses per-student keys.
