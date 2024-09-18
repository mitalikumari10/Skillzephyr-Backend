const aws = require('aws-sdk');
const dynamoDB = new aws.DynamoDB.DocumentClient();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const SECRET_KEY = 'xyxyxy';

const razorpay = new Razorpay({
  key_id: 'rzp_test_v2477Ctg5BxIwp',
  key_secret: 'm4tmOl0LJmEKhmRcgvUc1xF5',
});

// Fetch courses
exports.homepage = async (event) => {
  const params = {
    TableName: 'SkillzephyrTable', 
    ProjectionExpression: 'courseId, trailer, banner, courseDetails.#n',
    ExpressionAttributeNames: { '#n': 'name' }
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

// Course page
exports.coursepage = async (event) => {
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

// Login a user
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
exports.profile = async (event) => {
  const token = event.headers.Authorization && event.headers.Authorization.split(' ')[1];
  
  console.log('Token received:', token);

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    const username = decoded.username;

    console.log('Decoded username:', username);

    if (!username) {
      return {
        statusCode: 401,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Headers': 'Content-Type',
          'Access-Control-Allow-Methods': 'GET',
        },
        body: JSON.stringify({ message: 'Unauthorized' }),
      };
    }

    const params = {
      TableName: 'Users',
      Key: { username },
    };

    const userData = await dynamoDB.get(params).promise();

    if (!userData.Item) {
      return {
        statusCode: 404,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Headers': 'Content-Type',
          'Access-Control-Allow-Methods': 'GET',
        },
        body: JSON.stringify({ message: 'User not found' }),
      };
    }

    return {
      statusCode: 200,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'GET',
      },
      body: JSON.stringify(userData.Item),
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
      body: JSON.stringify({ message: 'Unauthorized', error: error.message }),
    };
  }
};


// Check if course is purchased
exports.checkCoursePurchase = async (event) => {
  const { username, courseId } = JSON.parse(event.body);

  const params = {
    TableName: 'Users',
    Key: { username: username }
  };

  try {
    const data = await dynamoDB.get(params).promise();
    const purchasedCourses = data.Item.coursesPurchased || [];
    
    const isPurchased = purchasedCourses.some(course => course.courseId === courseId);
    
    return {
      statusCode: 200,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'POST',
      },
      body: JSON.stringify({ isPurchased }),
    };
  } catch (error) {
    console.error('Error checking course purchase:', error);
    return {
      statusCode: 500,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'POST',
      },
      body: JSON.stringify({ message: 'Error checking course purchase', error: error.message }),
    };
  }
};
