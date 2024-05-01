// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TwoFactorAuth {
    struct User {
        address publicKey;
        bytes32 seed;
        uint64 lastGeneratedAt;
        uint otpLength;
        uint otp; // Store OTP for comparison during authentication
        mapping(bytes32 => bool) recoveryCodeUsed;
        mapping(bytes32 => bool) sessionTokens;
        mapping(address => bool) whitelistedIPs;
    }

    mapping(string => User) public users;
    mapping(string => uint) public otpExpiry;
    mapping(string => mapping(address => uint)) public failedAuthAttempts;
    mapping(address => bool) public admins;

    event UserRegistered(string username, address publicKey);
    event OTPGenerated(string username, uint otp);
    event UserAuthenticated(string username);
    event AuthenticationFailed(string username);
    event UserRemoved(string username);
    event RecoveryCodeGenerated(string username, bytes32 recoveryCode);
    event AdminAdded(address admin);
    event AdminRemoved(address admin);
    event SessionTokenGenerated(string username, bytes32 sessionToken);
    event SessionTokenExpired(string username, bytes32 sessionToken);

    modifier onlyAdmin() {
        require(admins[msg.sender], "Only admin can call this function");
        _;
    }

    constructor() {
        admins[msg.sender] = true;
    }

    // Function to register a user with their public key, initial OTP seed, and OTP length
    function registerUser(
        string memory username,
        address _publicKey,
        bytes32 _seed,
        uint _otpLength,
        uint _otpExpiry
    ) external {
        require(
            users[username].publicKey == address(0),
            "Username already exists"
        );

        // Initialize the User struct without the mappings
        User storage newUser = users[username];
        newUser.publicKey = _publicKey;
        newUser.seed = _seed;
        newUser.lastGeneratedAt = 0;
        newUser.otpLength = _otpLength;

        otpExpiry[username] = _otpExpiry;
        emit UserRegistered(username, _publicKey);
    }

    // Function to generate OTP for a registered user
    function generateOTP(string memory username) public returns (uint) {
        User storage user = users[username];
        require(user.publicKey != address(0), "User not registered");
        require(
            block.timestamp > user.lastGeneratedAt + otpExpiry[username],
            "Wait for OTP expiration"
        );

        // Generate OTP based on timestamp, seed, and length
        user.otp =
            uint(keccak256(abi.encodePacked(block.timestamp, user.seed))) %
            (10 ** user.otpLength);

        user.lastGeneratedAt = uint64(block.timestamp);

        emit OTPGenerated(username, user.otp);
        return user.otp;
    }

    // Function to authenticate user based on public key and OTP
    function authenticate(string memory username, uint _otp) external {
        User storage user = users[username];
        require(user.publicKey != address(0), "User not registered");
        require(
            failedAuthAttempts[username][msg.sender] < 3,
            "Too many failed attempts"
        );

        uint otp = user.otp;
        if (otp == _otp) {
            // Reset failed auth attempts
            delete failedAuthAttempts[username][msg.sender];

            // Add session token
            bytes32 sessionToken = keccak256(
                abi.encodePacked(username, msg.sender, block.timestamp)
            );
            user.sessionTokens[sessionToken] = true;
            emit SessionTokenGenerated(username, sessionToken);

            emit UserAuthenticated(username);
        } else {
            // Increment failed auth attempts
            failedAuthAttempts[username][msg.sender]++;
            emit AuthenticationFailed(username);
        }
    }

    // Function to unregister a user
    function unregisterUser(string memory username) external {
        require(users[username].publicKey != address(0), "User not registered");
        delete users[username];
        delete otpExpiry[username];
        emit UserRemoved(username);
    }

    // Function to generate recovery code for a user
    function generateRecoveryCode(
        string memory username,
        bytes32 _recoveryCode
    ) external onlyAdmin {
        users[username].recoveryCodeUsed[_recoveryCode] = false;
        emit RecoveryCodeGenerated(username, _recoveryCode);
    }

    // Function to use recovery code for account recovery
    function useRecoveryCode(
        string memory username,
        bytes32 _recoveryCode
    ) external {
        User storage user = users[username];
        require(
            !user.recoveryCodeUsed[_recoveryCode],
            "Recovery code already used"
        );
        user.recoveryCodeUsed[_recoveryCode] = true;
        failedAuthAttempts[username][user.publicKey] = 0;
    }

    // Function to add an admin
    function addAdmin(address _admin) external onlyAdmin {
        admins[_admin] = true;
        emit AdminAdded(_admin);
    }

    // Function to remove an admin
    function removeAdmin(address _admin) external onlyAdmin {
        admins[_admin] = false;
        emit AdminRemoved(_admin);
    }

    // Function to generate session token for user
    function generateSessionToken(
        string memory username,
        address _user
    ) external {
        require(
            msg.sender == _user || admins[msg.sender],
            "Only user or admin can generate session token"
        );
        User storage user = users[username];
        bytes32 sessionToken = keccak256(
            abi.encodePacked(username, _user, block.timestamp)
        );
        user.sessionTokens[sessionToken] = true;
        emit SessionTokenGenerated(username, sessionToken);
    }

    // Function to invalidate session token
    function invalidateSessionToken(
        string memory username,
        bytes32 sessionToken
    ) external {
        User storage user = users[username];
        require(
            user.sessionTokens[sessionToken],
            "Session token does not exist"
        );
        delete user.sessionTokens[sessionToken];
        emit SessionTokenExpired(username, sessionToken);
    }

    // Function to whitelist IP address
    function whitelistIP(string memory username, address _ip) external {
        User storage user = users[username];
        user.whitelistedIPs[_ip] = true;
    }

    // Function to remove IP address from whitelist
    function removeWhitelistedIP(string memory username, address _ip) external {
        User storage user = users[username];
        user.whitelistedIPs[_ip] = false;
    }

    // Function to check if IP is whitelisted
    function isIPWhitelisted(
        string memory username,
        address _ip
    ) external view returns (bool) {
        User storage user = users[username];
        return user.whitelistedIPs[_ip];
    }
}
