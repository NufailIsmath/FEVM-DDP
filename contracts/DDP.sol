// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";

contract DDP is Initializable, PausableUpgradeable, AccessControlUpgradeable, UUPSUpgradeable {
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 public constant DEV_ROLE = keccak256("DEV_ROLE");
    bytes32 public constant REVIEWER_ROLE = keccak256("REVIEWER_ROLE");
    bytes32 public constant QA_ROLE = keccak256("QA_ROLE");

    struct User {
        address userAddress;
        bytes32 userHandle;
        IERC20 currency;
        uint256 stakedAmount;
        bool isRewarded;
    }

    struct Task {
        bytes32 projectId;
        bytes32 taskId;
        string taskDetails;
        User dev;
        mapping(address => User) reviewer;
        uint256 reviewerCount;
        mapping(address => User) qa;
        uint256 qaCount;
        uint256 maxReviewer;
        uint256 maxQa;
        Reward reward;
        uint256 stakedAmount;
        IERC20 stakedCurrency;
        uint256 deadline;
        address owner;
        bool isStaked;
        uint256 taskStatus;
        uint256 contributorStakeAmount;
        mapping(address => bool) isContributors;
    }

    struct Reward {
        uint256 devRewardPerc;
        uint256 reviewerRewardPerc;
        uint256 qaRewardPerc;
        string creatorStakedHash;
    }

    IERC721 public DDPTaskNFT;
    IERC721 public DDPTaskAssigneeNFT;

    mapping(address => mapping(bytes32 => Task)) _tasksOfACreators;
    mapping(address => User) public userProfiles;

    event StakedForTaskCreation(
        bytes32 projectId,
        bytes32 taskId,
        uint256 amount,
        IERC20 currency,
        address owner
    );
    event TaskCreated(bytes32 projectId, bytes32 taskId, address owner);
    event UserRegistered(address user, bytes32 userHandle);
    event JoinedTask(bytes32 taksId, address user, bytes32 userRole);
    event UserStaked(address user, uint256 amount, uint256 totalAmount);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(IERC721 _ddpTaskNFT, IERC721 _ddpTaskAssigneeNFT) public initializer {
        DDPTaskNFT = _ddpTaskNFT;
        DDPTaskAssigneeNFT = _ddpTaskAssigneeNFT;

        __Pausable_init();
        __AccessControl_init();
        __UUPSUpgradeable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(PAUSER_ROLE, msg.sender);
        _grantRole(UPGRADER_ROLE, msg.sender);
    }

    function pause() public onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() public onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    function _authorizeUpgrade(address newImplementation)
        internal
        override
        onlyRole(UPGRADER_ROLE)
    {}

    function registerUser(string memory userHandleStr) public {
        bytes32 userHandle = getUserStrToBytes(userHandleStr);
        require(userHandle[0] != 0, "DDP: User handle cannot be empty");
        require(
            userProfiles[msg.sender].userHandle != userHandle &&
                userProfiles[msg.sender].userAddress != msg.sender,
            "DDP: User already exists"
        );

        User storage user = userProfiles[msg.sender];
        user.userAddress = msg.sender;
        user.userHandle = userHandle;
        user.isRewarded = false;

        emit UserRegistered(msg.sender, userHandle);
    }

    function userStake(IERC20 currency, uint256 amount) public {
        require(
            userProfiles[msg.sender].userAddress == msg.sender,
            "DDP: Access only for registered user"
        );
        User storage user = userProfiles[msg.sender];
        user.currency = currency;
        user.stakedAmount += amount;

        emit UserStaked(msg.sender, amount, user.stakedAmount);
    }

    function getUserStrToBytes(string memory userHandleStr)
        public
        pure
        returns (bytes32 userHandle)
    {
        bytes memory isStringEmpty = bytes(userHandleStr);
        if (isStringEmpty.length == 0) {
            return 0x00;
        }

        assembly {
            userHandle := mload(add(userHandleStr, 32))
        }
    }

    function stakeForTaskCreation(
        bytes32 projectId,
        bytes32 taskId,
        uint256 amount,
        IERC20 currency
    ) public {
        require(
            userProfiles[msg.sender].userAddress == msg.sender,
            "DDP: Access only for registered user"
        );
        require(amount > 1 ether, "DDP: Not enough stake");
        Task storage task = _tasksOfACreators[msg.sender][taskId];
        require(!task.isStaked, "DDP: Task has been Staked already");
        task.projectId = projectId;
        task.taskId = taskId;
        task.stakedAmount = amount;
        task.stakedCurrency = currency;
        task.owner = msg.sender;
        task.isStaked = true;

        currency.transferFrom(msg.sender, address(this), amount);

        emit StakedForTaskCreation(projectId, taskId, amount, currency, msg.sender);
    }

    function createTask(
        bytes32 taskId,
        string memory taskDetails,
        uint256 deadline,
        uint256 devRewardPerc,
        uint256 reviewerRewardPerc,
        uint256 qaRewardPerc,
        string memory stakeTxHash,
        uint256 maxReviewer,
        uint256 maxQa,
        uint256 contributorStakeAmount
    ) public {
        require(
            userProfiles[msg.sender].userAddress == msg.sender,
            "DDP: Access only for registered user"
        );
        require(_tasksOfACreators[msg.sender][taskId].isStaked, "DDP: Task should be staked");
        require(
            _tasksOfACreators[msg.sender][taskId].owner == msg.sender,
            "DDP: Task owner mismatched"
        );
        Reward memory reward = Reward(devRewardPerc, reviewerRewardPerc, qaRewardPerc, stakeTxHash);
        Task storage task = _tasksOfACreators[msg.sender][taskId];
        task.taskDetails = taskDetails;
        task.deadline = deadline;
        task.reward = reward;
        task.maxReviewer = maxReviewer;
        task.maxQa = maxQa;
        task.contributorStakeAmount = contributorStakeAmount;
        task.taskStatus = 1;

        DDPTaskNFT.safeMint(msg.sender, taskDetails);

        emit TaskCreated(_tasksOfACreators[msg.sender][taskId].projectId, taskId, msg.sender);
    }

    function _getUserRole(bytes32 userRole) private pure returns (uint256) {
        if (userRole == DEV_ROLE) {
            return 1;
        } else if (userRole == REVIEWER_ROLE) {
            return 2;
        } else {
            return 3;
        }
    }

    function joinTask(
        bytes32 taskId,
        address taskOwner,
        bytes32 userRole
    ) public {
        require(_tasksOfACreators[taskOwner][taskId].taskId == taskId, "DDP: Invalid Task");
        require(
            userRole == DEV_ROLE || userRole == REVIEWER_ROLE || userRole == QA_ROLE,
            "DDP: Invalid Role"
        );
        require(
            !_tasksOfACreators[msg.sender][taskId].isContributors[msg.sender],
            "DDP: Already a contributor"
        );
        require(
            userProfiles[msg.sender].stakedAmount >=
                _tasksOfACreators[taskOwner][taskId].contributorStakeAmount,
            "DDP: Not enough stake"
        );

        uint256 role = _getUserRole(userRole);
        Task storage task = _tasksOfACreators[taskOwner][taskId];
        if (role == 1) {
            task.dev = userProfiles[msg.sender];
            task.isContributors[msg.sender] = true;

            DDPTaskAssigneeNFT.safeMint(msg.sender, task.taskDetails); // for now task details as URI
        } else if (role == 2) {
            require(task.maxReviewer > task.reviewerCount, "DDP: Reviewer max reached");
            task.reviewer[msg.sender] = userProfiles[msg.sender];
            task.isContributors[msg.sender] = true;

            DDPTaskAssigneeNFT.safeMint(msg.sender, task.taskDetails); // for now task details as URI
        } else {
            require(task.maxQa > task.qaCount, "DDP: QA max reached");
            task.qa[msg.sender] = userProfiles[msg.sender];
            task.isContributors[msg.sender] = true;

            DDPTaskAssigneeNFT.safeMint(msg.sender, task.taskDetails); // for now task details as URI
        }

        emit JoinedTask(taskId, msg.sender, userRole);
    }

    function getTaskDetails(bytes32 taskId, address owner) public view returns (bytes32) {
        return _tasksOfACreators[owner][taskId].taskId;
    }

    /* TODO: taskStatusUpdate
    * Who is updating the status
    *
    
    */
}
