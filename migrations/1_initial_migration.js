const TwoFactorAuth = artifacts.require("TwoFactorAuth");

module.exports = function (deployer) {
  deployer.deploy(TwoFactorAuth);
};
