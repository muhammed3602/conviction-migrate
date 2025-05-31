# DataNest Secure Storage

A decentralized document storage and management system built on the Stacks blockchain, enabling businesses to securely store, manage, and control access to sensitive documents while maintaining a comprehensive audit trail.

## Overview

DataNest provides small businesses with a secure and transparent solution for managing sensitive documents. The system enables:

- Business registration on the blockchain
- Secure document reference storage
- Granular access control management
- Comprehensive audit logging
- Versioned document tracking

## Architecture

The system is built around a single smart contract that manages business registrations, document references, access permissions, and audit trails.

```mermaid
graph TD
    A[Business Owner] -->|Register Business| B[Business Registry]
    A -->|Upload Document| C[Document Storage]
    C -->|Store| D[Document References]
    C -->|Log| E[Audit Trail]
    A -->|Manage Access| F[Permission System]
    G[Employees/Partners] -->|Access Documents| C
    F -->|Control| G
    C -->|Record| E
```

### Core Components

1. **Business Registry**: Stores business information and ownership
2. **Document Storage**: Manages document metadata and references
3. **Permission System**: Controls access rights
4. **Audit System**: Tracks all document interactions

## Contract Documentation

### Permission Levels

- `PERMISSION-NONE (u0)`: No access
- `PERMISSION-VIEW (u1)`: View-only access
- `PERMISSION-EDIT (u2)`: Can edit documents
- `PERMISSION-ADMIN (u3)`: Can manage permissions
- `PERMISSION-OWNER (u4)`: Full control

### Action Types

- `ACTION-CREATE (u1)`: Document creation
- `ACTION-VIEW (u2)`: Document access
- `ACTION-EDIT (u3)`: Document modification
- `ACTION-SHARE (u4)`: Permission changes
- `ACTION-DELETE (u5)`: Document deletion

## Getting Started

### Prerequisites

- Clarinet
- Stacks wallet
- Node.js environment

### Basic Usage

1. Register a business:
```clarity
(contract-call? .datanest register-business "business123" "ACME Corp")
```

2. Add a document:
```clarity
(contract-call? .datanest add-document 
    "business123" 
    "doc123" 
    "Contract.pdf" 
    "Service agreement" 
    0x1234... 
    "legal")
```

3. Grant access:
```clarity
(contract-call? .datanest grant-document-permission 
    "business123" 
    "doc123" 
    'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM 
    u1)
```

## Function Reference

### Business Management

```clarity
(register-business (business-id (string-ascii 64)) (name (string-ascii 256)))
```
Registers a new business on the platform.

### Document Management

```clarity
(add-document 
    (business-id (string-ascii 64))
    (document-id (string-ascii 64))
    (name (string-ascii 256))
    (description (string-utf8 500))
    (document-hash (buff 32))
    (document-type (string-ascii 64)))
```
Adds a new document to the system.

```clarity
(update-document 
    (business-id (string-ascii 64))
    (document-id (string-ascii 64))
    (name (string-ascii 256))
    (description (string-utf8 500))
    (document-hash (buff 32))
    (document-type (string-ascii 64)))
```
Updates an existing document.

### Access Control

```clarity
(grant-document-permission 
    (business-id (string-ascii 64))
    (document-id (string-ascii 64))
    (user principal)
    (permission-level uint))
```
Grants access permissions to a user.

```clarity
(revoke-document-permission 
    (business-id (string-ascii 64))
    (document-id (string-ascii 64))
    (user principal))
```
Revokes access permissions from a user.

## Development

### Testing

1. Clone the repository
2. Install dependencies
3. Run tests:
```bash
clarinet test
```

### Local Development

1. Start Clarinet console:
```bash
clarinet console
```

2. Deploy contract:
```bash
clarinet deploy
```

## Security Considerations

### Access Control
- Only business owners can register new documents
- Permission levels are strictly enforced
- All access attempts are logged
- Document owners have full control

### Data Privacy
- Only document references are stored on-chain
- Actual documents should be stored off-chain in encrypted form
- Access control is managed through permission levels
- Audit trail maintains accountability

### Limitations
- Document hashes must be managed securely off-chain
- Permission changes require admin access
- No document content encryption on-chain
- Limited to 64-character business and document IDs