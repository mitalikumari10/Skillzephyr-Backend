const aws = require('aws-sdk');
const dynamoDB = new aws.DynamoDB.DocumentClient();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Razorpay = require('razorpay');

const SECRET_KEY = 'xyxyxy'; // Replace with a secure key in production


// Replace these with your Razorpay API Key and Secret
const razorpay = new Razorpay({
  key_id: 'rzp_test_v2477Ctg5BxIwp',
  key_secret: 'm4tmOl0LJmEKhmRcgvUc1xF5',
});

// Fetch courses
exports.create = async (event) => {
  const params = {
    TableName: 'SkillzephyrTable', 
    ProjectionExpression: 'courseId, trailer, banner, courseDetails, features, price, validity, courseFor, instructor, learnings, mission, perksAndBenefits, FAQ'
  };

  try {
    const data = await dynamoDB.scan(params).promise();
    return {
      statusCode: 200,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'GET',
      },
      body: JSON.stringify(data.Items),
    };
  } catch (error) {
    console.error('Error fetching course data:', error);
    return {
      statusCode: 500,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'GET'
      },
      body: JSON.stringify({ message: 'Error fetching course data', error: error.message }),
    };
  }
};

// Register a new user
exports.registerUser = async (event) => {
  const { username, password, email } = JSON.parse(event.body);
  const hashedPassword = await bcrypt.hash(password, 10);

  const params = {
    TableName: 'Users',
    Item: {
      username: username,
      password: hashedPassword,
      email: email
    },
  };

  try {
    await dynamoDB.put(params).promise();
    return {
      statusCode: 201,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'POST',
      },
      body: JSON.stringify({ message: 'User registered successfully' })
    };
  } catch (error) {
    console.error('Error registering user:', error);
    return {
      statusCode: 500,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'POST',
      },
      body: JSON.stringify({ message: 'Error registering user', error: error.message })
    };
  }
};
exports.loginUser = async (event) => {
  const { username, password } = JSON.parse(event.body);

  const params = {
    TableName: 'Users',
    Key: { username: username },
  };

  try {
    const data = await dynamoDB.get(params).promise();
    if (!data.Item) {
      return {
        statusCode: 404,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Headers': 'Content-Type',
          'Access-Control-Allow-Methods': 'POST',
        },
        body: JSON.stringify({ message: 'User not found' })
      };
    }

    const isPasswordValid = await bcrypt.compare(password, data.Item.password);
    if (!isPasswordValid) {
      return {
        statusCode: 401,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Headers': 'Content-Type',
          'Access-Control-Allow-Methods': 'POST',
        },
        body: JSON.stringify({ message: 'Invalid credentials' })
      };
    }

    const token = jwt.sign({ username: username }, SECRET_KEY, { expiresIn: '1h' });

    // Return the token and user data
    return {
      statusCode: 200,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'POST',
      },
      body: JSON.stringify({ token: token, user: { username: data.Item.username, email: data.Item.email } })
    };
  } catch (error) {
    console.error('Error logging in:', error);
    return {
      statusCode: 500,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'POST',
      },
      body: JSON.stringify({ message: 'Error logging in', error: error.message })
    };
  }
};

// Verify JWT token
exports.validateToken = (event) => {
  const token = event.headers.Authorization && event.headers.Authorization.split(' ')[1];

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    return {
      statusCode: 200,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'POST',
      },
      body: JSON.stringify({ valid: true, decoded: decoded })
    };
  } catch (error) {
    console.error('Error validating token:', error);
    return {
      statusCode: 401,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'POST',
      },
      body: JSON.stringify({ valid: false, message: 'Invalid token', error: error.message })
    };
  }
};

// Profile management
exports.profile = async (event) => {
  const token = event.headers.Authorization && event.headers.Authorization.split(' ')[1];

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    const params = {
      TableName: 'Users',
      Key: { username: decoded.username }
    };
    const userData = await dynamoDB.get(params).promise();
    return {
      statusCode: 200,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'GET',
      },
      body: JSON.stringify(userData.Item)
    };
  } catch (error) {
    console.error('Error fetching profile:', error);
    return {
      statusCode: 401,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'GET',
      },
      body: JSON.stringify({ message: 'Unauthorized', error: error.message })
    };
  }
};

exports.updateProfile = async (event) => {
  const token = event.headers.Authorization && event.headers.Authorization.split(' ')[1];
  const { courseId, courseName } = JSON.parse(event.body);

  try {
      const decoded = jwt.verify(token, SECRET_KEY);

      // Fetch user profile
      const getUserParams = {
          TableName: 'Users',
          Key: { username: decoded.username },
      };

      const userData = await dynamoDB.get(getUserParams).promise();

      if (!userData.Item) {
          return {
              statusCode: 404,
              headers: {
                  'Access-Control-Allow-Origin': '*',
                  'Access-Control-Allow-Headers': 'Content-Type',
                  'Access-Control-Allow-Methods': 'POST',
              },
              body: JSON.stringify({ message: 'User not found' })
          };
      }

      // Add the new course to the user's profile
      const updatedCourses = [...userData.Item.courses, { courseId, courseName }];

      const updateUserParams = {
          TableName: 'Users',
          Key: { username: decoded.username },
          UpdateExpression: 'set courses = :c',
          ExpressionAttributeValues: {
              ':c': updatedCourses,
          },
          ReturnValues: 'UPDATED_NEW',
      };

      await dynamoDB.update(updateUserParams).promise();

      return {
          statusCode: 200,
          headers: {
              'Access-Control-Allow-Origin': '*',
              'Access-Control-Allow-Headers': 'Content-Type',
              'Access-Control-Allow-Methods': 'POST',
          },
          body: JSON.stringify({ message: 'Profile updated successfully' }),
      };

  } catch (error) {
      return {
          statusCode: 500,
          headers: {
              'Access-Control-Allow-Origin': '*',
              'Access-Control-Allow-Headers': 'Content-Type',
              'Access-Control-Allow-Methods': 'POST',
          },
          body: JSON.stringify({ message: 'Error updating profile', error: error.message })
      };
  }
};

exports.createPaymentOrder = async (event) => {
  const { amount, currency, receipt } = JSON.parse(event.body);

  const options = {
      amount: amount * 100, // Amount is in smallest unit, so multiply by 100
      currency,
      receipt,
  };

  try {
      const order = await razorpay.orders.create(options);
      return {
          statusCode: 200,
          headers: {
              'Access-Control-Allow-Origin': '*',
              'Access-Control-Allow-Headers': 'Content-Type',
              'Access-Control-Allow-Methods': 'POST',
          },
          body: JSON.stringify({ orderId: order.id }),
      };
  } catch (error) {
      console.error('Error creating Razorpay order:', error);
      return {
          statusCode: 500,
          headers: {
              'Access-Control-Allow-Origin': '*',
              'Access-Control-Allow-Headers': 'Content-Type',
              'Access-Control-Allow-Methods': 'POST',
          },
          body: JSON.stringify({ message: 'Error creating Razorpay order', error: error.message }),
      };
  }
};

exports.verifyPayment = async (event) => {
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = JSON.parse(event.body);
  const crypto = require('crypto');

  const generated_signature = crypto.createHmac('sha256', 'YOUR_RAZORPAY_KEY_SECRET')
      .update(razorpay_order_id + '|' + razorpay_payment_id)
      .digest('hex');

  if (generated_signature === razorpay_signature) {
      // Add logic to update the user's profile with the purchased course here
      const { courseId, username } = JSON.parse(event.body);
      const params = {
          TableName: 'Users',
          Key: { username: username },
          UpdateExpression: 'SET coursesPurchased = list_append(if_not_exists(coursesPurchased, :empty_list), :course)',
          ExpressionAttributeValues: {
              ':course': [courseId],
              ':empty_list': []
          },
          ReturnValues: 'UPDATED_NEW'
      };

      try {
          await dynamoDB.update(params).promise();
          return {
              statusCode: 200,
              headers: {
                  'Access-Control-Allow-Origin': '*',
                  'Access-Control-Allow-Headers': 'Content-Type',
                  'Access-Control-Allow-Methods': 'POST',
              },
              body: JSON.stringify({ message: 'Payment verified and course added to profile' }),
          };
      } catch (error) {
          console.error('Error updating user profile:', error);
          return {
              statusCode: 500,
              headers: {
                  'Access-Control-Allow-Origin': '*',
                  'Access-Control-Allow-Headers': 'Content-Type',
                  'Access-Control-Allow-Methods': 'POST',
              },
              body: JSON.stringify({ message: 'Error updating user profile', error: error.message }),
          };
      }
  } else {
      return {
          statusCode: 400,
          headers: {
              'Access-Control-Allow-Origin': '*',
              'Access-Control-Allow-Headers': 'Content-Type',
              'Access-Control-Allow-Methods': 'POST',
          },
          body: JSON.stringify({ message: 'Invalid signature' }),
      };
  }
};