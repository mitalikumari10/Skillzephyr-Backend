const AWS = require('aws-sdk');
const cognito = new AWS.CognitoIdentityServiceProvider();

const USER_POOL_ID = 'us-east-1_GebKSCNYx';
const CLIENT_ID = '6rq5quslok037iumv1r6f03alv';

exports.registerUser = async (event) => {
  const { username, password, email } = JSON.parse(event.body);

  const params = {
    UserPoolId: USER_POOL_ID,
    Username: username,
    UserAttributes: [
      {
        Name: 'email',
        Value: email,
      },
    ],
    TemporaryPassword: password, // Use a temporary password initially
    MessageAction: 'SUPPRESS', // Suppress the invitation email
  };

  try {
    await cognito.adminCreateUser(params).promise();
    await cognito.adminSetUserPassword({
      UserPoolId: USER_POOL_ID,
      Username: username,
      Password: password,
      Permanent: true, // Mark the password as permanent
    }).promise();
    return {
      statusCode: 201,
      body: JSON.stringify({ message: 'User registered successfully' }),
    };
  } catch (error) {
    console.error('Error registering user:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ message: 'Error registering user', error: error.message }),
    };
  }
};

exports.loginUser = async (event) => {
  const { username, password } = JSON.parse(event.body);

  const params = {
    AuthFlow: 'USER_PASSWORD_AUTH',
    ClientId: CLIENT_ID,
    AuthParameters: {
      USERNAME: username,
      PASSWORD: password,
    },
  };

  try {
    const result = await cognito.initiateAuth(params).promise();
    return {
      statusCode: 200,
      body: JSON.stringify(result),
    };
  } catch (error) {
    console.error('Error logging in user:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ message: 'Error logging in user', error: error.message }),
    };
  }
};

exports.confirmUser = async (event) => {
  const { username, code } = JSON.parse(event.body);

  const params = {
    UserPoolId: USER_POOL_ID,
    Username: username,
    ConfirmationCode: code,
  };

  try {
    await cognito.adminConfirmSignUp(params).promise();
    return {
      statusCode: 200,
      body: JSON.stringify({ message: 'User confirmed successfully' }),
    };
  } catch (error) {
    console.error('Error confirming user:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ message: 'Error confirming user', error: error.message }),
    };
  }
};
