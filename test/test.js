const TwoFactorAuth = artifacts.require('TwoFactorAuth');

contract('TwoFactorAuth', function (accounts) {
   let twoFactorAuth;
   const user = { address: accounts[0] };
   const admin = { address: accounts[1] };

   beforeEach(async function () {
      twoFactorAuth = await TwoFactorAuth.new({ from: user.address });
   });

   describe('registerUser', function () {
      it('should register a new user', async function () {
         const username = 'user1';
         const tx = await twoFactorAuth.registerUser(username, user.address, web3.utils.randomHex(32), 6, 60 * 60 * 24);
         const event = tx.logs.find(log => log.event === 'UserRegistered');
         assert.isDefined(event, 'UserRegistered event should be emitted');
         assert.strictEqual(event.args.username, username, 'Event should contain correct username');
         assert.strictEqual(event.args.publicKey, user.address, 'Event should contain correct publicKey');
      });

      it('should not allow duplicate username registration', async function () {
         const username = 'user1';
         await twoFactorAuth.registerUser(username, user.address, web3.utils.randomHex(32), 6, 60 * 60 * 24);
         try {
            await twoFactorAuth.registerUser(username, user.address, web3.utils.randomHex(32), 6, 60 * 60 * 24);
            assert.fail('Expected an error');
         } catch (error) {
            assert.include(error.message, 'Username already exists');
         }
      });
   });

   describe('generateOTP', function () {
      it('should generate OTP for the user', async function () {
         const username = 'user1';
         await twoFactorAuth.registerUser(username, user.address, web3.utils.randomHex(32), 6, 60 * 60 * 24);
         const tx = await twoFactorAuth.generateOTP(username);
         const event = tx.logs.find(log => log.event === 'OTPGenerated');
         assert.isDefined(event, 'OTPGenerated event should be emitted');
         assert.strictEqual(event.args.username, username, 'Event should contain correct username');
      });

      it('should not allow generating OTP for unregistered user', async function () {
         const username = 'user1';
         try {
            await twoFactorAuth.generateOTP(username);
            assert.fail('Expected an error');
         } catch (error) {
            assert.include(error.message, 'User not registered');
         }
      });

      it('should expire OTP after OTP expiry duration', async function () {
         const username = 'user1';
         await twoFactorAuth.registerUser(username, user.address, web3.utils.randomHex(32), 6, 10000); // 1 second expiry
         await twoFactorAuth.generateOTP(username);
         await new Promise(resolve => setTimeout(resolve, 2000)); // Wait for OTP to expire
         try {
            await twoFactorAuth.generateOTP(username);
         } catch (error) {
            assert.include(error.message, 'Wait for OTP expiration');
         }
      });
   });

   // Add test cases for remaining functions...

   describe('unregisterUser', function () {
      it('should unregister a user', async function () {
         const username = 'user1';
         await twoFactorAuth.registerUser(username, user.address, web3.utils.randomHex(32), 6, 60 * 60 * 24);
         const tx = await twoFactorAuth.unregisterUser(username);
         const event = tx.logs.find(log => log.event === 'UserRemoved');
         assert.isDefined(event, 'UserRemoved event should be emitted');
         assert.strictEqual(event.args.username, username, 'Event should contain correct username');
      });
   });

   describe('authenticate', function () {
      it('should authenticate user with correct OTP', async function () {
         // Generate a unique username
         const username = 'user_' + Date.now().toString();

         // Register the new user
         await twoFactorAuth.registerUser(username, user.address, web3.utils.randomHex(32), 6, 60 * 60 * 24);

         // Generate OTP from the contract
         await twoFactorAuth.generateOTP(username);

         // Fetch the user data from the contract
         const userData = await twoFactorAuth.users(username);

         // Retrieve the OTP from the user's data
         const otp = userData.otp;

         // Authenticate with the retrieved OTP
         const tx = await twoFactorAuth.authenticate(username, otp);
         const event = tx.logs.find(log => log.event === 'UserAuthenticated');

         // Assertions
         assert.isDefined(event, 'UserAuthenticated event should be emitted');
         assert.strictEqual(event.args.username, username, 'Event should contain correct username');
      });

      it('should not authenticate user with incorrect OTP', async function () {
         // Generate a unique username
         const username = 'user_' + Date.now().toString();

         // Register the new user
         await twoFactorAuth.registerUser(username, user.address, web3.utils.randomHex(32), 6, 60 * 60 * 24);

         // Get the number of failed attempts before authentication
         const initialFailedAttempts = await twoFactorAuth.failedAuthAttempts(username, user.address);

         // Generate OTP from the contract
         await twoFactorAuth.generateOTP(username);

         // Generate incorrect OTP
         const incorrectOTP = web3.utils.randomHex(6);

         // Try to authenticate with incorrect OTP
         await twoFactorAuth.authenticate(username, incorrectOTP);

         // Get the number of failed attempts after authentication
         const finalFailedAttempts = await twoFactorAuth.failedAuthAttempts(username, user.address);

         // Ensure the number of failed attempts has increased by 1
         assert.strictEqual(finalFailedAttempts.toString(), (initialFailedAttempts.toNumber() + 1).toString(), 'Failed attempts should increase by 1');

      });






      describe('generateRecoveryCode', function () {
         it('should generate a recovery code for the user', async function () {
            const username = 'user_recovery_1'; // Unique username
            const recoveryCode = web3.utils.randomHex(32); // Generate random hex bytes
            const tx = await twoFactorAuth.generateRecoveryCode(username, recoveryCode);
            const event = tx.logs.find(log => log.event === 'RecoveryCodeGenerated');

            // Assertions
            assert.isDefined(event, 'RecoveryCodeGenerated event should be emitted');
            assert.strictEqual(event.args.username, username, 'Event should contain correct username');
            assert.strictEqual(event.args.recoveryCode, recoveryCode, 'Event should contain correct recoveryCode');
         });
      });



      describe('addAdmin', function () {
         it('should add an admin', async function () {
            const admin = accounts[1];
            const tx = await twoFactorAuth.addAdmin(admin);
            const event = tx.logs.find(log => log.event === 'AdminAdded');

            // Assertions
            assert.isDefined(event, 'AdminAdded event should be emitted');
            assert.strictEqual(event.args.admin, admin, 'Event should contain correct admin address');
         });
      });

      describe('removeAdmin', function () {
         it('should remove an admin', async function () {
            const admin = accounts[1];
            await twoFactorAuth.addAdmin(admin);

            // Ensure admin is initially added
            assert.isTrue(await twoFactorAuth.admins(admin), 'Admin should be initially added');

            // Remove the admin
            const tx = await twoFactorAuth.removeAdmin(admin);
            const event = tx.logs.find(log => log.event === 'AdminRemoved');

            // Assertions
            assert.isDefined(event, 'AdminRemoved event should be emitted');
            assert.strictEqual(event.args.admin, admin, 'Event should contain correct admin address');
         });
      });


      it('should not allow non-admin to remove admin', async function () {
         await twoFactorAuth.addAdmin(admin.address, { from: user.address });
         try {
            await twoFactorAuth.removeAdmin(admin.address, { from: accounts[2] });
            assert.fail('Expected an error');
         } catch (error) {
            assert.include(error.message, 'Only admin can call this function', 'Error message should indicate that only an admin can perform this action');
         }
      });

   });







});
