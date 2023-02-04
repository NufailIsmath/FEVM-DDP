// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/math/SafeMathUpgradeable.sol";

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";

contract DDP is Initializable, PausableUpgradeable, AccessControlUpgradeable, UUPSUpgradeable {
    using SafeMathUpgradeable for uint256;

    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 public constant DEV_ROLE = keccak256("DEV_ROLE");
    bytes32 public constant REVIEWER_ROLE = keccak256("REVIEWER_ROLE");
    bytes32 public constant TESTER_ROLE = keccak256("TESTER_ROLE");

    struct User {
        address userAddress;
        bytes32 userHandle;
        IERC20 currency;
        uint256 stakedAmount;
        //mapping(bytes32 => uint256) stakedPerTask;
        bool isRewarded;
    }

    struct Task {
        bytes32 projectId;
        bytes32 taskId;
        string taskDetails;
        User dev;
        User[] reviewers;
        User[] testers;
        uint256 maxReviewer;
        uint256 maxTesters;
        Reward reward;
        uint256 stakedAmount;
        IERC20 stakedCurrency;
        uint256 deadline;
        address owner;
        bool isStaked;
        uint256 taskStatus;
        uint256 contributorStakeAmount;
        uint256 redoCount;
    }

    struct Reward {
        uint256 devRewardPerc;
        uint256 reviewerRewardPerc;
        uint256 testerRewardPerc;
        string creatorStakedHash;
    }

    IERC721 public DDPTaskNFT;
    IERC721 public DDPTaskAssigneeNFT;

    mapping(address => mapping(bytes32 => Task)) _tasksOfACreators;
    mapping(address => User) public userProfiles;
    mapping(address => mapping(bytes32 => bool)) _taskContributors;
    mapping(address => mapping(bytes32 => uint256)) _stakedPerTask;
    mapping(address => mapping(bytes32 => bool)) _blacklisted;

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
    event TaskInProgress(bytes32 taskId, address taskOwner, uint256 status);
    event TaskToBeReviewed(bytes32 taskId, address taskOwner, uint256 status);
    event TaskInReview(bytes32 taskId, address taskOwner, uint256 status);
    event TaskReviewFailed(bytes32 taskId, address taskOwner, uint256 status);
    event TaskBackToProgress(bytes32 taskId, address taskOwner, uint256 status);
    event TaskReadyToTest(bytes32 taskId, address taskOwner, uint256 status);
    event TaskInTesting(bytes32 taskId, address taskOwner, uint256 status);
    event TaskTestCompleted(bytes32 taskId, address taskOwner, uint256 status);
    event TaskTestFailed(bytes32 taskId, address taskOwner, uint256 status);
    event TaskCompleted(bytes32 taskId, address taskOwner, uint256 status);

    //TODO: Take percentage as 1000 decimal place

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
        uint256 devRewardPerc, // 1 60,000
        uint256 reviewerRewardPerc, // 1-3
        uint256 testerRewardPerc, //1-3
        string memory stakeTxHash,
        uint256 maxReviewer,
        uint256 maxTesters,
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
        uint256 totalPercentage = devRewardPerc.add(reviewerRewardPerc.add(testerRewardPerc));
        require(totalPercentage == 100000, "DDP: Percentage doesn't add up to 100");
        Reward memory reward = Reward(
            devRewardPerc,
            reviewerRewardPerc,
            testerRewardPerc,
            stakeTxHash
        );
        Task storage task = _tasksOfACreators[msg.sender][taskId];
        task.taskDetails = taskDetails;
        task.deadline = deadline;
        task.reward = reward;
        task.maxReviewer = maxReviewer;
        task.maxTesters = maxTesters;
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
        require(
            userProfiles[msg.sender].userAddress == msg.sender,
            "DDP: Access only for registered user"
        );
        require(_tasksOfACreators[taskOwner][taskId].taskId == taskId, "DDP: Invalid Task");
        require(
            userRole == DEV_ROLE || userRole == REVIEWER_ROLE || userRole == TESTER_ROLE,
            "DDP: Invalid Role"
        );
        require(!_blacklisted[msg.sender][taskId], "DDP: User is being blacklisted");
        require(!_taskContributors[msg.sender][taskId], "DDP: Already a contributor");
        require(
            userProfiles[msg.sender].stakedAmount >=
                _tasksOfACreators[taskOwner][taskId].contributorStakeAmount,
            "DDP: Not enough stake"
        );

        uint256 role = _getUserRole(userRole);
        Task storage task = _tasksOfACreators[taskOwner][taskId];
        if (role == 1) {
            task.dev = userProfiles[msg.sender];
        } else if (role == 2) {
            require(task.maxReviewer > task.reviewers.length, "DDP: Reviewer max reached");
            task.reviewers.push(userProfiles[msg.sender]);
        } else {
            require(task.maxTesters > task.testers.length, "DDP: Tester max reached");
            task.testers.push(userProfiles[msg.sender]);
        }

        _taskContributors[msg.sender][taskId] = true;
        _stakedPerTask[msg.sender][taskId] = _tasksOfACreators[taskOwner][taskId]
            .contributorStakeAmount;
        DDPTaskAssigneeNFT.safeMint(msg.sender, task.taskDetails); // for now task details as URI Should be done at task completion

        emit JoinedTask(taskId, msg.sender, userRole);
    }

    function getTaskDetails(bytes32 taskId, address owner) public view returns (bytes32) {
        return _tasksOfACreators[owner][taskId].taskId;
    }

    function taskStatusUpdate(
        bytes32 taskId,
        address taskOwner,
        uint256 from,
        uint256 to
    ) public {
        require(_taskContributors[msg.sender][taskId], "DDP: Only contributors allowed");
        require(from <= 9, "DDP: Invalid From");
        require(to <= 9, "DDP: Invalid To");

        if (from == 0 && to == 1) {
            // in progress
            _taskToInProgress(taskId, taskOwner, from, to);
        } else if (from == 1 && to == 2) {
            // ready for review
            _taskToReview(taskId, taskOwner, from, to);
        } else if (from == 2 && to == 3) {
            // reviewing
            _taskToReviewing(taskId, taskOwner, from, to);
        } else if (from == 3 && to == 8) {
            // updated review failed - review failed
            _taskReviewFailed(taskId, taskOwner, from, to);
        } else if (from == 8 && to == 1) {
            // back to in progress - review failed
            _taskBackToProgress(taskId, taskOwner, from, to);
        } else if (from == 3 && to == 4) {
            // ready to test
            _taskReadyToTest(taskId, taskOwner, from, to);
        } else if (from == 4 && to == 5) {
            // testing
            _taskTesting(taskId, taskOwner, from, to);
        } else if (from == 5 && to == 9) {
            // back to in progress - test failed
            _taskTestFailed(taskId, taskOwner, from, to);
        } else if (from == 9 && to == 1) {
            // back to in progress - test failed
            _taskBackToProgress(taskId, taskOwner, from, to);
        } else if (from == 5 && to == 6) {
            // test completed
            _taskTestCompleted(taskId, taskOwner, from, to);
            //_taskCompleted(taskId, taskOwner);
        } else if (from == 6 && to == 7) {
            _taskCompleted(taskId, taskOwner, from, to);
        } else {
            // Restricted to task owner
            _switchTaskStatus(taskId, taskOwner, from, to);
        }
    }

    function _switchTaskStatus(
        bytes32 taskId,
        address taskOwner,
        uint256 from,
        uint256 to
    ) private {
        require(
            _tasksOfACreators[taskOwner][taskId].owner == msg.sender,
            "DDP: Restricted to task owner"
        );
        if (to == 1) {
            _taskToInProgress(taskId, taskOwner, from, to);
        } else if (to == 2) {
            _taskToReview(taskId, taskOwner, from, to);
        } else if (to == 3) {
            _taskToReviewing(taskId, taskOwner, from, to);
        } else if (to == 4) {
            _taskReadyToTest(taskId, taskOwner, from, to);
        } else if (to == 5) {
            _taskTesting(taskId, taskOwner, from, to);
        } else if (to == 6) {
            _taskTestCompleted(taskId, taskOwner, from, to);
        } else if (to == 7) {
            _taskCompleted(taskId, taskOwner, from, to);
        } else {
            revert("DDP: Invlaid Input");
        }
    }

    function _taskToInProgress(
        bytes32 taskId,
        address taskOwner,
        uint256 from,
        uint256 to
    ) private {
        require(
            _getContributorRole(taskId, taskOwner, msg.sender) == 1 ||
                _getContributorRole(taskId, taskOwner, msg.sender) == 0,
            "DDP: Restricted to dev and task owner"
        );
        Task storage task = _tasksOfACreators[taskOwner][taskId];
        require(task.taskStatus == from, "DDP: Task status invalid");
        task.taskStatus = to;

        emit TaskInProgress(taskId, taskOwner, to);
    }

    function _taskToReview(
        bytes32 taskId,
        address taskOwner,
        uint256 from,
        uint256 to
    ) private {
        require(
            _getContributorRole(taskId, taskOwner, msg.sender) == 1 ||
                _getContributorRole(taskId, taskOwner, msg.sender) == 0,
            "DDP: Restricted to dev and task owner"
        );
        Task storage task = _tasksOfACreators[taskOwner][taskId];
        require(task.taskStatus == from, "DDP: Task status invalid");
        task.taskStatus = to;

        emit TaskToBeReviewed(taskId, taskOwner, to);
    }

    function _taskToReviewing(
        bytes32 taskId,
        address taskOwner,
        uint256 from,
        uint256 to
    ) private {
        require(
            _getContributorRole(taskId, taskOwner, msg.sender) == 2 ||
                _getContributorRole(taskId, taskOwner, msg.sender) == 0,
            "DDP: Restricted to reviewer and task owner"
        );
        Task storage task = _tasksOfACreators[taskOwner][taskId];
        require(task.taskStatus == from, "DDP: Task status invalid");
        task.taskStatus = to;

        emit TaskInReview(taskId, taskOwner, to);
    }

    function _taskReviewFailed(
        bytes32 taskId,
        address taskOwner,
        uint256 from,
        uint256 to
    ) private {
        require(
            _getContributorRole(taskId, taskOwner, msg.sender) == 2 ||
                _getContributorRole(taskId, taskOwner, msg.sender) == 0,
            "DDP: Restricted to reviewer and task owner"
        );
        Task storage task = _tasksOfACreators[taskOwner][taskId];
        require(task.taskStatus == from, "DDP: Task status invalid");
        task.taskStatus = to;
        task.redoCount++;

        address devAddress = task.dev.userAddress;
        if (task.redoCount == 1) {
            delete _stakedPerTask[task.dev.userAddress][taskId];
            userProfiles[task.dev.userAddress].stakedAmount = userProfiles[devAddress]
                .stakedAmount
                .sub(task.contributorStakeAmount);
            //TODO: transfer the amount to a staking pool contract

            //emit DevTaskStakeRemoved(taskId, task.dev.userAddress, task.contributorStakeAmount);
        } else {
            //TODO: Kick out Dev change status to TODO
            // kickout dev
            User memory emptyUser = userProfiles[address(0)];
            _blacklisted[devAddress][taskId] = true;
            task.dev = emptyUser;

            task.taskStatus = 0;

            //emit DevKickedOut(address devAddress, taskId);
        }

        emit TaskReviewFailed(taskId, taskOwner, to);
    }

    function _taskBackToProgress(
        bytes32 taskId,
        address taskOwner,
        uint256 from,
        uint256 to
    ) private {
        require(
            _getContributorRole(taskId, taskOwner, msg.sender) == 1 ||
                _getContributorRole(taskId, taskOwner, msg.sender) == 0,
            "DDP: Restricted to dev and task owner"
        );
        Task storage task = _tasksOfACreators[taskOwner][taskId];
        require(task.taskStatus == from, "DDP: Task status invalid");

        task.taskStatus = to;

        emit TaskBackToProgress(taskId, taskOwner, to);
    }

    function _taskReadyToTest(
        bytes32 taskId,
        address taskOwner,
        uint256 from,
        uint256 to
    ) private {
        require(
            _getContributorRole(taskId, taskOwner, msg.sender) == 2 ||
                _getContributorRole(taskId, taskOwner, msg.sender) == 0,
            "DDP: Restricted to reviewer and task owner"
        );
        Task storage task = _tasksOfACreators[taskOwner][taskId];
        require(task.taskStatus == from, "DDP: Task status invalid");

        task.taskStatus = to;

        emit TaskReadyToTest(taskId, taskOwner, to);
    }

    function _taskTesting(
        bytes32 taskId,
        address taskOwner,
        uint256 from,
        uint256 to
    ) private {
        require(
            _getContributorRole(taskId, taskOwner, msg.sender) == 3 ||
                _getContributorRole(taskId, taskOwner, msg.sender) == 0,
            "DDP: Restricted to tester and task owner"
        );
        Task storage task = _tasksOfACreators[taskOwner][taskId];
        require(task.taskStatus == from, "DDP: Task status invalid");

        task.taskStatus = to;

        emit TaskInTesting(taskId, taskOwner, to);
    }

    // TODO: Task TEST FAILED
    function _taskTestFailed(
        bytes32 taskId,
        address taskOwner,
        uint256 from,
        uint256 to
    ) private {
        require(
            _getContributorRole(taskId, taskOwner, msg.sender) == 3 ||
                _getContributorRole(taskId, taskOwner, msg.sender) == 0,
            "DDP: Restricted to tester and task owner"
        );
        Task storage task = _tasksOfACreators[taskOwner][taskId];
        require(task.taskStatus == from, "DDP: Task status invalid");

        task.taskStatus = to;

        emit TaskTestFailed(taskId, taskOwner, to);
    }

    function _taskTestCompleted(
        bytes32 taskId,
        address taskOwner,
        uint256 from,
        uint256 to
    ) private {
        require(
            _getContributorRole(taskId, taskOwner, msg.sender) == 3 ||
                _getContributorRole(taskId, taskOwner, msg.sender) == 0,
            "DDP: Restricted to tester and task owner"
        );
        Task storage task = _tasksOfACreators[taskOwner][taskId];
        require(task.taskStatus == from, "DDP: Task status invalid");

        task.taskStatus = to;

        emit TaskTestCompleted(taskId, taskOwner, to);
    }

    /* TODO: taskStatusUpdate
    * Who is updating the status
    *
    
    */

    /* When completing task reward calculation

    * Reward 40/2 for QA and Reviewer
    * Reviewer/reviewerCount
    */

    // TODO: _taskCompleted
    function _taskCompleted(
        bytes32 taskId,
        address taskOwner,
        uint256 from,
        uint256 to
    ) private {
        require(
            _getContributorRole(taskId, taskOwner, msg.sender) == 0,
            "DDP: Restricted task owner"
        );
        Task storage task = _tasksOfACreators[taskOwner][taskId];
        require(task.taskStatus == from, "DDP: Task status invalid");

        (uint256 devReward, uint256 reviewerReward, uint256 testerReward) = _getRewardCalculation(
            taskId,
            taskOwner
        );

        // reward the dev
        _rewardDev(task, devReward);

        // reward the reviewers
        _rewardReviewers(task, reviewerReward);

        // reward the testers
        _rewardTesters(task, testerReward);

        task.taskStatus = to;

        emit TaskCompleted(taskId, taskOwner, to);
    }

    function _rewardDev(Task storage task, uint256 amount) private {
        require(!task.dev.isRewarded, "DDP: Dev is already being rewarded");
        task.dev.isRewarded = true;
        task.stakedCurrency.transfer(task.dev.userAddress, amount);

        // emit TrasnferDevReward(task.taskId, task.dev.userAddress, amount);
    }

    function _rewardReviewers(Task storage task, uint256 amount) private {
        for (uint8 i = 0; i < task.reviewers.length; i++) {
            require(!task.reviewers[i].isRewarded, "DDP: Reviewer is already being rewarded");
            task.reviewers[i].isRewarded = true;
            task.stakedCurrency.transfer(task.reviewers[i].userAddress, amount);

            //emit TransferReviewerReward(task.taskId, task.reviewers[i].userAddress, amount);
        }
    }

    function _rewardTesters(Task storage task, uint256 amount) private {
        for (uint8 i = 0; i < task.testers.length; i++) {
            require(!task.testers[i].isRewarded, "DDP: Tester is already being rewarded");
            task.testers[i].isRewarded = true;
            task.stakedCurrency.transfer(task.testers[i].userAddress, amount);

            //emit TransferTesterReward(task.taskId, task.testers[i].userAddress, amount);
        }
    }

    function _getRewardCalculation(bytes32 taskId, address taskOwner)
        public
        view
        returns (
            uint256,
            uint256,
            uint256
        )
    {
        Task memory task = _tasksOfACreators[taskOwner][taskId];
        uint256 devRewardAmount = task.stakedAmount.mul(task.reward.devRewardPerc).div(100 * 10**3);
        uint256 totalReviewerRewardAmount = task
            .stakedAmount
            .mul(task.reward.reviewerRewardPerc)
            .div(100 * 10**3);
        uint256 reviewerRewardAmount = totalReviewerRewardAmount.div(task.reviewers.length);
        uint256 totalTesterRewardAmount = task.stakedAmount.mul(task.reward.testerRewardPerc).div(
            100 * 10**3
        );
        uint256 testerRewardAmount = totalTesterRewardAmount.div(task.testers.length);

        return (devRewardAmount, reviewerRewardAmount, testerRewardAmount);
    }

    function _getContributorRole(
        bytes32 taskId,
        address taskOwner,
        address user
    ) private view returns (uint256) {
        Task memory task = _tasksOfACreators[taskOwner][taskId];
        if (task.dev.userAddress == user) {
            return 1;
        }

        if (task.owner == user) {
            return 0;
        }

        bool isReviewer = false;

        for (uint256 i = 0; i < task.reviewers.length; i++) {
            if (task.reviewers[i].userAddress == user) {
                isReviewer = true;
                break;
            }
        }

        if (isReviewer) {
            return 2;
        } else {
            return 3;
        }
    }

    //TODO: UpdateTaskDetails (IPFS URI)
}
