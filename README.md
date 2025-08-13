# RefugeID

A blockchain-powered decentralized identity platform that provides secure, self-sovereign identities for displaced persons, enabling access to critical services like healthcare, financial aid, and education without traditional documentation.

---

## Overview

RefugeID leverages the Stacks blockchain and Clarity smart contracts to create a decentralized identity solution for displaced persons, such as refugees or stateless individuals. The platform ensures privacy, security, and portability of identities, allowing users to access services in a trustless environment. It addresses the real-world problem of identity loss during crises, where traditional documents (e.g., passports, IDs) are unavailable or unverifiable.

The system consists of four main smart contracts that work together to create, verify, and manage self-sovereign identities:

1. **Identity Creation Contract** – Allows users to create decentralized identities (DIDs) with encrypted personal data.
2. **Credential Issuance Contract** – Enables trusted organizations (e.g., NGOs, governments) to issue verifiable credentials (e.g., proof of medical history, aid eligibility).
3. **Access Control Contract** – Manages selective disclosure of identity data to service providers via zero-knowledge proofs.
4. **Service Provider Registry Contract** – Maintains a decentralized registry of verified service providers (e.g., clinics, aid agencies) to ensure trust.

---

## Features

- **Self-Sovereign Identity Creation**: Users generate and control their own decentralized identities, stored securely on-chain.
- **Verifiable Credentials**: Trusted entities issue credentials (e.g., vaccination records, aid eligibility) that are cryptographically verifiable.
- **Selective Disclosure**: Users share only necessary data with service providers using zero-knowledge proofs, preserving privacy.
- **Trusted Service Provider Network**: A decentralized registry ensures only verified providers can access identity data.
- **Portable and Interoperable**: Identities and credentials are accessible globally, compatible with any Stacks-based service.
- **Tamper-Proof and Transparent**: Blockchain ensures immutability of identity records and auditability of interactions.

---

## Smart Contracts

### Identity Creation Contract
- Creates a decentralized identity (DID) for a user, linked to their Stacks address.
- Stores encrypted personal data (e.g., name, birth date) on-chain, accessible only by the user’s private key.
- Generates a public-private key pair for zero-knowledge proof-based interactions.

### Credential Issuance Contract
- Allows trusted issuers (e.g., NGOs, health organizations) to issue verifiable credentials (e.g., proof of identity, medical records).
- Credentials are cryptographically signed and linked to the user’s DID.
- Supports revocation of credentials by issuers in case of errors or fraud.

### Access Control Contract
- Manages selective disclosure of identity data using zero-knowledge proofs.
- Users grant granular access (e.g., share only vaccination status) to service providers.
- Logs access requests on-chain for transparency and auditing.

### Service Provider Registry Contract
- Maintains a decentralized list of verified service providers (e.g., hospitals, aid agencies).
- Providers are onboarded via a governance process (e.g., DAO or admin approval).
- Ensures only registered providers can request identity data, preventing unauthorized access.

---

## Installation

1. Install [Clarinet CLI](https://docs.hiro.so/clarinet/getting-started).
2. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/refugeid.git
   ```
3. Run tests:
   ```bash
   npm test
   ```
4. Deploy contracts:
   ```bash
   clarinet deploy
   ```

---

## Usage

Each smart contract is designed to operate independently but integrates seamlessly to form the RefugeID ecosystem. Below is a basic workflow:

1. **User Creates Identity**: A displaced person calls the Identity Creation Contract to generate a DID and store encrypted data.
2. **Issuer Adds Credentials**: An NGO or government uses the Credential Issuance Contract to issue credentials (e.g., proof of refugee status).
3. **Service Provider Verification**: A provider (e.g., clinic) queries the Service Provider Registry Contract to confirm their eligibility, then requests specific data via the Access Control Contract.
4. **User Grants Access**: The user approves the request, sharing only the required data (e.g., medical history) using zero-knowledge proofs.

Refer to individual contract documentation for detailed function calls, parameters, and usage examples.

---

## License

MIT License
