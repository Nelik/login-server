# Interview Project - login and sign up server 

## Configuration

### NodeJS
This project was set up with NodeJS 16.X. Recommended version is 16.X or higher.
- Check installed version: `$ node --version`
- If NodeJS is missing or installed version is incompatible, then:
  - Check if NVM is installed `$ nvm -- version`
  - If NVM is not installed:
      - Uninstall existing NodeJS (if any present)
      - Download and install NVM zip installer from: https://github.com/coreybutler/nvm-windows
  - Install NodeJS using NVM: `$ nvm install 16.13.2` `$ nvm use 16.13.2`
  - Install NPX with `npm instal npx`
  - Install dependecies with `npm install` in the root project directory.

### AWS DynamoDB
Set up an AWS DynamoDB in Oregon region and set the correcponding AWS profile as default profile on your local.

More detailed instructions can be found here: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/SettingUp.DynamoWebService.html.

In DynamoDB create a table 'InterviewProjectUsers' with 'username' as a partition key.

### AWS Secrets Manager
In the same account and region, set up AWS Secrets Manager.

More detailed information can be found heere: https://docs.aws.amazon.com/secretsmanager/latest/userguide/asm_access.html.

Choose some random, long, secure secret for JWT token generation and store it in the Secrets Manager as plain text under the name 'jwtKey'.

### Redis
For Mac and Linux users open your terminal and type the following commands:
```
wget https://download.redis.io/releases/redis-6.2.4.tar.gz
tar xzf redis-6.2.4.tar.gz
cd redis-6.2.4
make
```

For Windows users can install WSL (Windows Subsystem for Linux). Here’s the official tutorial from Microsoft: https://docs.microsoft.com/en-us/windows/wsl/install.
 
After the installation ends, start the server with this command:
```
src/redis-server
```

### Run
To start the application run `npm start` in the root project directory.

### Deployment
The server has been deployed in AWS on EC2 instance and listens on port 8080.

Access through: http://34.220.165.194:8080/.

**When starting communication with server, please send GET request to '/csrf-token' and store returned token as CSRF token in cookies first.**
