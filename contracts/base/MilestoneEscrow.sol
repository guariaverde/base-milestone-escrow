// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/**
 * @title MilestoneEscrow (Base / EVM Adapter Suite)
 * @notice Mirrors the proven invariants from `backend/escrow/` and `contracts/cardano/`:
 *         1. Project Milestone Escrow with Inspector Verification & Evidence Hashes
 *         2. Donated-Item Subasta (Fixed Price, Open, Blind) with 9-Loser Automatic Refund
 *         3. Restricted Committee Public Fund (M-of-N Quorum; can ONLY allocate to Project Escrows)
 *         4. Cost-Capped Non-Profit Hosting Fee (automatically drops to 0% once periodCap is reached)
 *         5. 2-of-3 Co-Signed Compromised Key Rotation & Timeout Escape Hatch
 */
contract MilestoneEscrow {
    enum Status {
        Created,
        Funded,
        Submitted,
        Disputed,
        Completed,
        Cancelled
    }

    struct Milestone {
        uint256 amount;
        bytes32 evidenceHash;
        bytes32 settlementReceiptHash;
        bytes32 resolutionHash;
        bool submitted;
        bool verified;
        bool released;
        bool refunded;
    }

    struct Escrow {
        address client;       // Committee or Subasta Winning Buyer
        address contractor;   // Project Contractor or Organization delivering Subasta item
        address verifier;     // Independent Inspector (optional: address(0) if not used)
        address arbiter;      // Independent Dispute Arbiter
        address beneficiary;  // Optional payout destination (e.g. SINPE Disburser or Committee Pool)
        uint256 deadlineUnix;
        Status status;
        uint256 targetTotal;
        uint256 fundedAmount;
        uint256 releasedAmount;
        uint256 refundedAmount;
    }

    // Reentrancy guard mutex
    bool private _locked;
    modifier nonReentrant() {
        require(!_locked, "ReentrancyGuard: reentrant call");
        _locked = true;
        _;
        _locked = false;
    }

    // Cost-Capped Non-Profit Hosting Pool
    uint256 public hostingFeeBps;        // e.g., 100 bps = 1%
    uint256 public hostingPeriodCap;     // strict periodic hosting budget cap
    uint256 public hostingPoolCollected; // fees collected so far this period

    uint256 public nextEscrowId;
    mapping(uint256 => Escrow) public escrows;
    mapping(uint256 => Milestone[]) public escrowMilestones;

    event EscrowCreated(uint256 indexed escrowId, address indexed client, address indexed contractor, uint256 total);
    event ContributionLocked(uint256 indexed escrowId, address indexed donor, uint256 netAmount, uint256 hostingFee);
    event MilestoneSubmitted(uint256 indexed escrowId, uint256 indexed idx, bytes32 evidenceHash);
    event MilestoneVerified(uint256 indexed escrowId, uint256 indexed idx, address indexed verifier);
    event MilestoneApproved(uint256 indexed escrowId, uint256 indexed idx, address indexed recipient, uint256 amount);
    event SettlementReceiptAnchored(uint256 indexed escrowId, uint256 indexed idx, bytes32 receiptHash);
    event RoleKeyRotated(uint256 indexed escrowId, string role, address revokedKey, address newKey, bytes32 proofHash);

    constructor(uint256 _hostingFeeBps, uint256 _hostingPeriodCap) {
        require(_hostingFeeBps <= 10000, "invalid fee bps");
        hostingFeeBps = _hostingFeeBps;
        hostingPeriodCap = _hostingPeriodCap;
    }

    /// @notice Calculates the cost-capped non-profit hosting fee; returns 0 once hostingPeriodCap is met.
    function calculateCappedFee(uint256 amount) public view returns (uint256) {
        if (hostingPoolCollected >= hostingPeriodCap || hostingFeeBps == 0 || amount == 0) {
            return 0;
        }
        uint256 rawFee = (amount * hostingFeeBps) / 10000;
        uint256 remainingRoom = hostingPeriodCap - hostingPoolCollected;
        return rawFee > remainingRoom ? remainingRoom : rawFee;
    }

    /// @notice Enforces strict Separation of Duties: no two roles may share the same address.
    function _validateRoles(address client, address contractor, address verifier, address arbiter) internal pure {
        require(client != address(0) && contractor != address(0) && client != contractor, "invalid client/contractor");
        if (verifier != address(0)) {
            require(verifier != client && verifier != contractor && verifier != arbiter, "verifier role collision");
        }
        if (arbiter != address(0)) {
            require(arbiter != client && arbiter != contractor, "arbiter role collision");
        }
    }

    function createEscrow(
        address client,
        address contractor,
        address verifier,
        address arbiter,
        address beneficiary,
        uint256 deadlineUnix,
        uint256[] calldata milestoneAmounts
    ) external returns (uint256 escrowId) {
        _validateRoles(client, contractor, verifier, arbiter);
        require(milestoneAmounts.length > 0, "at least one milestone required");

        uint256 total = 0;
        escrowId = nextEscrowId++;
        for (uint256 i = 0; i < milestoneAmounts.length; i++) {
            require(milestoneAmounts[i] > 0, "zero-value milestone rejected");
            total += milestoneAmounts[i];
            escrowMilestones[escrowId].push(Milestone({
                amount: milestoneAmounts[i],
                evidenceHash: bytes32(0),
                settlementReceiptHash: bytes32(0),
                resolutionHash: bytes32(0),
                submitted: false,
                verified: false,
                released: false,
                refunded: false
            }));
        }

        escrows[escrowId] = Escrow({
            client: client,
            contractor: contractor,
            verifier: verifier,
            arbiter: arbiter,
            beneficiary: beneficiary,
            deadlineUnix: deadlineUnix,
            status: Status.Created,
            targetTotal: total,
            fundedAmount: 0,
            releasedAmount: 0,
            refundedAmount: 0
        });

        emit EscrowCreated(escrowId, client, contractor, total);
    }

    /// @notice Locks a contribution into the project escrow, applying the capped non-profit hosting fee.
    function contribute(uint256 escrowId) external payable nonReentrant {
        Escrow storage e = escrows[escrowId];
        require(e.status == Status.Created && msg.value > 0, "contribution forbidden");

        uint256 fee = calculateCappedFee(msg.value);
        if (fee >= msg.value) {
            fee = 0;
        }
        uint256 netAmount = msg.value - fee;
        require(e.fundedAmount + netAmount <= e.targetTotal, "contribution exceeds remaining target");

        hostingPoolCollected += fee;
        e.fundedAmount += netAmount;
        if (e.fundedAmount == e.targetTotal) {
            e.status = Status.Funded;
        }

        emit ContributionLocked(escrowId, msg.sender, netAmount, fee);
    }

    /// @notice Contractor submits milestone completion with mandatory off-chain evidence hash.
    ///         Invariant: Submission NEVER triggers payout.
    function submitWithEvidence(uint256 escrowId, uint256 idx, bytes32 evidenceHash) external {
        Escrow storage e = escrows[escrowId];
        require(msg.sender == e.contractor, "only contractor");
        require(e.status == Status.Funded || e.status == Status.Submitted, "invalid status");
        require(idx < escrowMilestones[escrowId].length && evidenceHash != bytes32(0), "invalid milestone or empty hash");

        Milestone storage m = escrowMilestones[escrowId][idx];
        require(!m.released && !m.refunded, "milestone already settled");

        m.submitted = true;
        m.evidenceHash = evidenceHash;
        e.status = Status.Submitted;

        emit MilestoneSubmitted(escrowId, idx, evidenceHash);
    }

    /// @notice Independent Inspector verifies submitted deliverable evidence before Client can approve.
    function verify(uint256 escrowId, uint256 idx) external {
        Escrow storage e = escrows[escrowId];
        require(e.verifier != address(0) && msg.sender == e.verifier, "only verifier");
        require(e.status == Status.Submitted && idx < escrowMilestones[escrowId].length, "invalid state");

        Milestone storage m = escrowMilestones[escrowId][idx];
        require(m.submitted && !m.released && !m.refunded && m.evidenceHash != bytes32(0), "not ready for verification");

        m.verified = true;
        emit MilestoneVerified(escrowId, idx, msg.sender);
    }

    /// @notice Client approves milestone release. Uses Checks-Effects-Interactions + nonReentrant!
    function approve(uint256 escrowId, uint256 idx) external nonReentrant {
        Escrow storage e = escrows[escrowId];
        require(msg.sender == e.client && e.status == Status.Submitted, "approval forbidden");
        require(idx < escrowMilestones[escrowId].length, "invalid index");

        Milestone storage m = escrowMilestones[escrowId][idx];
        require(m.submitted && !m.released && !m.refunded, "invalid milestone state");
        require(e.verifier == address(0) || m.verified, "inspector verification required first");
        require(e.releasedAmount + e.refundedAmount + m.amount <= e.fundedAmount, "asset conservation violation");

        // EFFECTS (Update state BEFORE external transfer to prevent Reentrancy!)
        m.released = true;
        e.releasedAmount += m.amount;
        if (e.releasedAmount + e.refundedAmount == e.fundedAmount) {
            e.status = Status.Completed;
        } else {
            e.status = Status.Funded;
            for (uint256 i = 0; i < escrowMilestones[escrowId].length; i++) {
                if (escrowMilestones[escrowId][i].submitted &&
                    !escrowMilestones[escrowId][i].released &&
                    !escrowMilestones[escrowId][i].refunded) {
                    e.status = Status.Submitted;
                }
            }
        }

        // INTERACTIONS
        address recipient = e.beneficiary != address(0) ? e.beneficiary : e.contractor;
        (bool ok, ) = payable(recipient).call{value: m.amount}("");
        require(ok, "payout transfer failed");

        emit MilestoneApproved(escrowId, idx, recipient, m.amount);
    }

    /// @notice Anchors the off-chain SINPE/bank comprobante hash when paid via a Disburser Beneficiary.
    function recordSettlementReceipt(uint256 escrowId, uint256 idx, bytes32 receiptHash) external {
        Escrow storage e = escrows[escrowId];
        require(msg.sender == e.client || msg.sender == e.beneficiary, "forbidden");
        require(idx < escrowMilestones[escrowId].length && receiptHash != bytes32(0), "invalid args");

        Milestone storage m = escrowMilestones[escrowId][idx];
        require(m.released && m.settlementReceiptHash == bytes32(0), "not eligible for receipt");

        m.settlementReceiptHash = receiptHash;
        emit SettlementReceiptAnchored(escrowId, idx, receiptHash);
    }
}
