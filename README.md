# blockchain-assignment

Q1 — Hyperledger Fabric Supply Chain Network

Objective

Build a permissioned blockchain network that records product creation, shipment, and delivery across multiple participants.

Network Setup Summary

Organizations: ManufacturerOrg, DistributorOrg, RetailerOrg

Channels:

manu-dist-channel — Manufacturer ↔ Distributor

dist-retail-channel — Distributor ↔ Retailer

Consensus: Solo/RAFT ordering service

Chaincode File: SupplyChain.sol

Chaincode Functions

createProduct(productID, name, details) → Create a new product entry

Initiatetransfer(productID, toOrg) → Record shipment to next participant

acceptTransfer(productID) → Confirm product receipt

GetProductHistory(productID) → View full product lifecycle

Simulation Steps

Manufacturer creates product P001.

Transfers it to Distributor → Retailer.

Each transaction recorded on its respective private channel.

Query confirms traceability across the entire chain.

Access Control and Consensus

Manufacturer can create products only.

Distributor can accept and transfer only.

Retailer can only view or mark received.

Endorsement policies prevent unauthorized modifications.



Q2 — Layer-2 Blockchain Security and Mitigation Demo

Objective

Evaluate Layer-2 blockchain security for financial applications by identifying threats, simulating vulnerabilities, and applying mitigations.

Threats Analyzed

Sybil Attack: Fake node identities to influence the network.

Double Spending: Same token spent twice before finality.

Smart Contract Exploit (Reentrancy): Attacker drains funds via recursive calls.

Simulation Environment

IDE: Remix Ethereum IDE

Contracts:

VulnerableBank.sol — Demonstrates reentrancy flaw

SecureBank.sol — Fixed version using ReentrancyGuard

Attacker.sol — Simulates malicious exploit attempt

Demonstration Steps

Deploy VulnerableBank and fund it with 5 ETH.

Deploy Attacker with the VulnerableBank address.

Execute attack() — shows how ETH is drained (bank → attacker + 1 ETH).

Deploy SecureBank and repeat — attack fails due to protection.

Mitigation Strategies

Sybil Attack: Use permissioned membership or PoS validation.

Double Spending: Adopt PBFT/Raft for finality and multiple endorsements.

Smart Contract Exploit: Apply ReentrancyGuard and code audits.

DoS / Spam: Rate-limiting and gas-based throttling.

Data Tampering: Use digital signatures and Fabric endorsement policies.

Example Outcome

VulnerableBank balance before attack → 5 ETH

After attack → 6 ETH (exploit success)

Attacker account → 1 ETH gained

SecureBank remains unaffected (attack reverted)
