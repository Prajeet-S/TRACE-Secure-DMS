# NYAAY VAULT – Secure Digital Document & Case Management System

NYAAY VAULT is a secure digital document and case management system designed to manage legal documents and case-related information with authentication, access control, document integrity verification, audit logging, and secure cloud storage.

The system provides separate workflows for:

- Police / Investigators
- Lawyers / Legal Officers
- Court Authorities

---

## Features

### 🔐 Authentication & Authorization

- User registration and login
- JWT-based authentication
- Role-based access control
- Password hashing
- OTP-based email verification
- Authentication throttling and security controls

### 📁 Secure Document Management

- Upload and manage case documents
- Document metadata stored in the database
- Actual files stored using Azure Blob Storage
- File integrity verification using SHA-256 hashes
- File download and content access
- Document replacement and deletion controls

### ⚖️ Case Management

- Create and manage cases
- Associate documents with cases
- Role-based case operations
- Track case-related activities

### 🔗 Document Integrity & Blockchain Ledger

The system maintains a blockchain-style immutable ledger for document-related actions.

Each block contains information such as:

- Document ID
- Case ID
- File hash
- User ID
- Action performed
- Previous block hash
- Current block hash
- Timestamp

This allows the system to verify whether recorded document information has been altered.

### 📋 Audit Logging

Important actions are recorded in audit logs, including document and case-related operations.

### 📧 OTP Verification

Email-based OTP verification is implemented for authentication-related workflows.

### ☁️ Azure Integration

Azure Blob Storage is used for storing uploaded documents.

The backend interacts with Azure Storage through Azure CLI using authenticated Azure CLI sessions rather than storing Azure storage keys directly in the source code.

---

## System Architecture

```text
                    ┌──────────────────────┐
                    │   React Frontend     │
                    │   (Vite)             │
                    └──────────┬───────────┘
                               │
                               │ HTTP / REST API
                               ▼
                    ┌──────────────────────┐
                    │   FastAPI Backend    │
                    │                      │
                    │ Authentication       │
                    │ Authorization        │
                    │ Case Management      │
                    │ Document Management  │
                    │ Audit Logging        │
                    └───────┬───────┬──────┘
                            │       │
                 ┌──────────┘       └──────────────┐
                 ▼                                 ▼
        ┌─────────────────┐              ┌──────────────────┐
        │ SQLite Database │              │ Azure Blob       │
        │                 │              │ Storage          │
        │ Users           │              │                  │
        │ Cases           │              │ Documents        │
        │ Documents       │              │                  │
        │ Audit Logs      │              └──────────────────┘
        │ Blockchain      │
        │ OTP records     │
        └─────────────────┘