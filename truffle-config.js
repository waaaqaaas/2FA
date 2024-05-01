module.exports = {
  networks: {
    development: {
      host: "127.0.0.1",     // Localhost (default: none)
      port: 7545,            // Standard Ganache port (default: none)
      network_id: "*",       // Match any network id
    },
    ganache: {
      host: "127.0.0.1",
      port: 7545,
      network_id: "*",
      networkCheckTimeout: 60000 // Timeout in milliseconds
    }

  },

  // Configure your compilers
  compilers: {
    solc: {
      version: "0.8.0",    // Fetch exact version from solc-bin (default: truffle's version)
      // Docker: false,    // Use "0.5.1" you've installed locally with docker (default: false)
      // settings: {       // See the solidity docs for advice about optimization and evmVersion
      //  optimizer: {
      //    enabled: false,
      //    runs: 200
      //  },
      //  evmVersion: "byzantium"
      // }
    },
  },
};
