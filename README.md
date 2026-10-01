# TRACE – Secure Digital Document & Case Management System

TRACE(Trusted Records, Access & Compliance Engine) is a secure digital document and case management system designed for managing legal documents and case-related information with authentication, role-based access control, document integrity verification, audit logging, and secure cloud storage.

The system provides dedicated workflows for:

- Police / Investigators
- Lawyers / Legal Officers
- Court Authorities

---

## Features

### 🔐 Authentication & Authorization

- User registration and login
- JWT-based authentication
- Role-based access control
- Secure password hashing
- OTP-based email verification
- Authentication throttling and security controls

### 📁 Secure Document Management

- Upload and manage case documents
- Store document metadata in the database
- Store actual documents using Azure Blob Storage
- SHA-256 file integrity verification
- Document download and content access
- Document replacement and deletion controls

### ⚖️ Case Management

- Create and manage cases
- Associate documents with cases
- Role-based access to case information
- Track case-related activities

### 🔗 Blockchain-Based Integrity Ledger

TRACE maintains a blockchain-style ledger for document-related actions.

Each blockchain block records information such as:

- Document ID
- Case ID
- File hash
- User ID
- Action performed
- Previous block hash
- Current block hash
- Timestamp

This provides a mechanism for verifying the integrity of recorded document information and detecting unauthorized changes.

### 📋 Audit Logging

System activities are recorded through audit logs, allowing document and case-related actions to be tracked.

### 📧 OTP Verification

TRACE uses email-based OTP verification for authentication-related workflows.

### ☁️ Azure Cloud Storage

Azure Blob Storage is used to store uploaded documents.

The backend interacts with Azure Storage using Azure CLI with authenticated Azure sessions rather than embedding Azure storage credentials in the source code.

---

## System Architecture

```text
                    ┌──────────────────────┐
                    │    React Frontend    │
                    │        (Vite)        │
                    └──────────┬───────────┘
                               │
                               │ REST API
                               ▼
                    ┌──────────────────────┐
                    │    FastAPI Backend   │
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
        │ OTP Records     │
        └─────────────────┘