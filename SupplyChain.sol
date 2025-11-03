// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title SupplyChain - Simple supply chain lifecycle in Solidity for Remix
/// @notice Manufacturer -> Distributor -> Retailer lifecycle with role-based access,
/// events, history, private-view simulation, and two-phase transfer to simulate consensus.

contract SupplyChain {
    enum Role { None, Manufacturer, Distributor, Retailer }
    enum Status { Created, InTransit, Received }

    struct EventEntry {
        uint256 timestamp;
        address actor;
        string action; // "Created", "Transferred", "Received", "Note: ..."
        string metadata; // arbitrary JSON or IPFS URI (encrypted off-chain if needed)
    }

    struct Product {
        string productId; // external ID (SKU)
        address owner;    // current custodian
        Role ownerRole;
        Status status;
        EventEntry[] history;
        bool exists;
    }

    // Access control
    mapping(address => Role) public roles;
    address public admin;

    // Products
    mapping(string => Product) private products; // productId -> Product

    // Two-phase transfers: productId -> pending recipient
    mapping(string => address) public pendingRecipient;

    // View permissions (simulate private channel): productId => address => allowed
    mapping(string => mapping(address => bool)) public viewPermissions;

    // Events
    event ProductCreated(string indexed productId, address indexed manufacturer);
    event TransferInitiated(string indexed productId, address indexed from, address indexed to);
    event TransferAccepted(string indexed productId, address indexed accepter);
    event ProductReceived(string indexed productId, address indexed receiver);
    event AccessGranted(string indexed productId, address indexed viewer);
    event AccessRevoked(string indexed productId, address indexed viewer);

    modifier onlyAdmin() {
        require(msg.sender == admin, "only admin");
        _;
    }

    modifier onlyRole(Role r) {
        require(roles[msg.sender] == r, "unauthorized role");
        _;
    }

    modifier productExists(string memory pid) {
        require(products[pid].exists, "product not found");
        _;
    }

    constructor() {
        admin = msg.sender;
        // admin can be given special powers to assign roles
        roles[msg.sender] = Role.None;
    }

    /// ADMIN functions to assign roles
    function assignRole(address account, Role r) external onlyAdmin {
        roles[account] = r;
    }

    function revokeRole(address account) external onlyAdmin {
        roles[account] = Role.None;
    }

    /// Manufacturer creates a product record.
    /// metadata can be an IPFS URI or encrypted payload (off-chain encryption recommended for private data)
    function createProduct(string calldata productId, string calldata metadata)
        external
        onlyRole(Role.Manufacturer)
    {
        require(!products[productId].exists, "already exists");
        Product storage p = products[productId];
        p.productId = productId;
        p.owner = msg.sender;
        p.ownerRole = roles[msg.sender];
        p.status = Status.Created;
        p.exists = true;

        // record history
        p.history.push(EventEntry(block.timestamp, msg.sender, "Created", metadata));

        // by default manufacturer, distributor, retailer addresses might be able to view
        viewPermissions[productId][msg.sender] = true;

        emit ProductCreated(productId, msg.sender);
    }

    /// Initiate transfer: only current owner may initiate. This sets a pendingRecipient that must accept.
    function initiateTransfer(string calldata productId, address to)
        external
        productExists(productId)
    {
        Product storage p = products[productId];
        require(msg.sender == p.owner, "only owner can initiate transfer");
        require(to != address(0), "invalid recipient");
        pendingRecipient[productId] = to;
        p.history.push(EventEntry(block.timestamp, msg.sender, "TransferInitiated", _addrToString(to)));
        p.status = Status.InTransit;
        emit TransferInitiated(productId, msg.sender, to);
    }

    /// Accept transfer: recipient calls this to accept. This two-step pattern reduces unauthorized updates (simulates consensus between two parties).
    function acceptTransfer(string calldata productId)
        external
        productExists(productId)
    {
        require(pendingRecipient[productId] == msg.sender, "no pending transfer to you");
        Product storage p = products[productId];

        address previousOwner = p.owner;
        p.owner = msg.sender;
        p.ownerRole = roles[msg.sender];
        p.history.push(EventEntry(block.timestamp, msg.sender, "TransferAccepted", ""));
        // clear pending
        pendingRecipient[productId] = address(0);

        emit TransferAccepted(productId, msg.sender);
    }

    /// Mark received by final recipient (could be same as acceptTransfer or separate)
    function markReceived(string calldata productId)
        external
        productExists(productId)
    {
        Product storage p = products[productId];
        require(msg.sender == p.owner, "only owner can mark received");
        p.status = Status.Received;
        p.history.push(EventEntry(block.timestamp, msg.sender, "Received", ""));
        emit ProductReceived(productId, msg.sender);
    }

    /// Grant and revoke view permission (admin or owner can grant)
    function grantView(string calldata productId, address viewer)
        external
        productExists(productId)
    {
        Product storage p = products[productId];
        require(msg.sender == admin || msg.sender == p.owner, "only admin or owner");
        viewPermissions[productId][viewer] = true;
        emit AccessGranted(productId, viewer);
    }

    function revokeView(string calldata productId, address viewer)
        external
        productExists(productId)
    {
        Product storage p = products[productId];
        require(msg.sender == admin || msg.sender == p.owner, "only admin or owner");
        viewPermissions[productId][viewer] = false;
        emit AccessRevoked(productId, viewer);
    }

    /// Read product summary - limited information; full history only if viewPermission granted.
    function getProductSummary(string calldata productId)
        external
        view
        productExists(productId)
        returns (string memory id, address ownerAddr, Role ownerR, Status stat)
    {
        Product storage p = products[productId];

        // Basic summary available to everyone: id, current owner, role and status
        // If you need to enforce stricter privacy, restrict this too.
        return (p.productId, p.owner, p.ownerRole, p.status);
    }

    /// Read full history — only permitted addresses can view. This simulates private channels / private data.
    function getProductHistory(string calldata productId)
        external
        view
        productExists(productId)
        returns (EventEntry[] memory)
    {
        require(viewPermissions[productId][msg.sender], "no view permission for this product");
        return products[productId].history;
    }

    /// Helper to add a freeform note to history by owner (audit log)
    function addNote(string calldata productId, string calldata note)
        external
        productExists(productId)
    {
        Product storage p = products[productId];
        require(msg.sender == p.owner, "only owner");
        p.history.push(EventEntry(block.timestamp, msg.sender, "Note", note));
    }

    /// Utility: convert address to string (limited)
    function _addrToString(address _addr) internal pure returns (string memory) {
        bytes20 value = bytes20(_addr);
        bytes16 hexSymbols = "0123456789abcdef";
        bytes memory str = new bytes(42);
        str[0] = '0';
        str[1] = 'x';
        for (uint i = 0; i < 20; i++) {
            str[2 + i*2] = hexSymbols[uint8(value[i] >> 4)];
            str[3 + i*2] = hexSymbols[uint8(value[i] & 0x0f)];
        }
        return string(str);
    }
}
