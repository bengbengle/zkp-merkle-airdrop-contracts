// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";
interface IPlonkVerifier {
    function verifyProof(bytes memory proof, uint[] memory pubSignals) external view returns (bool);
}

interface IERC20 {
    function transfer(address recipient, uint256 amount) external returns (bool);
}

/// @title 使用 MerkleTree 包含的 zk-proof 的示例空投合约。
contract PrivateAirdrop is Ownable {
    IERC20 public airdropToken; // 空投哪种代币
    uint public amountPerRedemption; // 每次赎回金额
    IPlonkVerifier verifier;

    bytes32 public root;

    mapping(bytes32 => bool) public nullifierSpent;

    uint256 constant SNARK_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    constructor(
        IERC20 _airdropToken,
        uint _amountPerRedemption,
        IPlonkVerifier _verifier,
        bytes32 _root
    ) {
        airdropToken = _airdropToken;
        amountPerRedemption = _amountPerRedemption;
        verifier = _verifier;
        root = _root;
    }

    /// @notice 验证证明，如果有效则收集空投，并阻止此证明再次工作。
    function collectAirdrop(bytes calldata proof, bytes32 nullifierHash) public {
        // 无效符不在该字段内
        require(uint256(nullifierHash) < SNARK_FIELD ,"Nullifier is not within the field");
        require(!nullifierSpent[nullifierHash], "Airdrop already redeemed"); // 空投已兑换

        uint[] memory pubSignals = new uint[](3);
        pubSignals[0] = uint256(root);
        pubSignals[1] = uint256(nullifierHash);
        pubSignals[2] = uint256(uint160(msg.sender));
        require(verifier.verifyProof(proof, pubSignals), "Proof verification failed");

        nullifierSpent[nullifierHash] = true;
        airdropToken.transfer(msg.sender, amountPerRedemption);
    }

   /// @notice 允许所有者 更新默克尔树的根。 
   /// @dev 可以移除 函数以使默克尔树不可变。如果删除，也可以删除可拥有的扩展程序以节省气体。
    function updateRoot(bytes32 newRoot) public onlyOwner {
        root = newRoot;
    }
}
