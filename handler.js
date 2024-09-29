const aws = require('aws-sdk');
const dynamoDB = new aws.DynamoDB.DocumentClient();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const SECRET_KEY = 'xyxyxy';
const s3 = new aws.S3();
const bucketName = 'cobuc';
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
        'Access-Control-Allow-Origin': 'http://localhost:3000',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'GET',
        'Access-Control-Allow-Credentials': 'true',
      },
      body: JSON.stringify(data.Items),
    };
  } catch (error) {
    console.error('Error fetching course data:', error);
    return {
      statusCode: 500,
      headers: {
        'Access-Control-Allow-Origin': 'http://localhost:3000',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'GET',
        'Access-Control-Allow-Credentials': 'true',
      },
      body: JSON.stringify({ message: 'Error fetching course data', error: error.message }),
    };
  }
};


// Main course page function
exports.coursepage = async (event) => {
  const { courseId } = JSON.parse(event.body);
  // Check if courseId is provided
  if (!courseId) {
      return {
          statusCode: 400,
          headers: {
              'Access-Control-Allow-Origin': 'http://localhost:3000',
              'Access-Control-Allow-Headers': 'Content-Type',
              'Access-Control-Allow-Methods': 'POST',
              'Access-Control-Allow-Credentials': 'true',
          },
          body: JSON.stringify({ message: 'Course ID is required' }),
      };
  }
  try {
      // Fetch course data from the courses table
      const courseParams = {
          TableName: 'SkillzephyrTable',
          Key: { courseId: courseId },
      };
      const courseData = await dynamoDB.get(courseParams).promise();
      if (!courseData.Item) {
          return {
              statusCode: 404,
              headers: {
                  'Access-Control-Allow-Origin': 'http://localhost:3000',
                  'Access-Control-Allow-Headers': 'Content-Type',
                  'Access-Control-Allow-Methods': 'POST',
                  'Access-Control-Allow-Credentials': 'true',
              },
              body: JSON.stringify({ message: 'Course not found' }),
          };
      }
      // Verify JWT from cookies
      const { isAuthorized, user } = verifyJwtFromCookies(event);
      // If not authorized, return course without presigned URL (show "Enroll" button)
      if (!isAuthorized) {
          return {
              statusCode: 200,
              headers: {
                  'Access-Control-Allow-Origin': 'http://localhost:3000',
                  'Access-Control-Allow-Headers': 'Content-Type',
                  'Access-Control-Allow-Methods': 'POST',
                  'Access-Control-Allow-Credentials': 'true',
              },
              body: JSON.stringify({ ...courseData.Item, buttonText: 'enroll' }),
          };
      }
      // Fetch user's purchased courses from the user's database
      const userParams = {
          TableName: 'Users',
          Key: { username: user.username },
      };
      const userData = await dynamoDB.get(userParams).promise();
      // Check if the user has already purchased the course
      const isCoursePurchased = userData.Item?.coursesPurchased?.some(course => course.courseId === courseId);
      // If the course is purchased, return with pre-signed URL and "Launch" button
      if (isCoursePurchased) {
          const presignedUrl = await generatePresignedUrl(courseId); // Generate the presigned URL based on courseId
          return {
              statusCode: 200,
              headers: {
                  'Access-Control-Allow-Origin': 'http://localhost:3000',
                  'Access-Control-Allow-Headers': 'Content-Type',
                  'Access-Control-Allow-Methods': 'POST',
                  'Access-Control-Allow-Credentials': 'true',
              },
              body: JSON.stringify({ ...courseData.Item, presignedUrl, buttonText: 'Launch' }),
          };
      }
      // If the course is not purchased, return course data with the "Enroll" button
      return {
          statusCode: 200,
          headers: {
              'Access-Control-Allow-Origin': 'http://localhost:3000',
              'Access-Control-Allow-Headers': 'Content-Type',
              'Access-Control-Allow-Methods': 'POST',
              'Access-Control-Allow-Credentials': 'true',
          },
          body: JSON.stringify({ ...courseData.Item, buttonText: 'enroll' }),
      };
  } catch (error) {
      console.error('Error fetching course data:', error);
      return {
          statusCode: 500,
          headers: {
              'Access-Control-Allow-Origin': 'http://localhost:3000',
              'Access-Control-Allow-Headers': 'Content-Type',
              'Access-Control-Allow-Methods': 'POST',
              'Access-Control-Allow-Credentials': 'true',
          },
          body: JSON.stringify({ message: 'Error fetching course data', error: error.message }),
      };
  }
};

// Function to generate the presigned URL for the course content
async function generatePresignedUrl(cId) {
  const params = {
      Bucket: bucketName,
      Key: `${cId}.mp4`, // Use the course ID as the key for the S3 object
      Expires: 60 * 60 // URL expiration time in seconds (5 minutes)
  };
  try {
      const url = await s3.getSignedUrlPromise('getObject', params); // Generate the pre-signed URL
      return url;
  } catch (error) {
      console.error('Error generating pre-signed URL:', error);
      throw new Error('Could not generate pre-signed URL');
  }
}


// Register a new user
exports.registerUser = async (event) => {
  const { username, password, email } = JSON.parse(event.body);
  if (!username || !password || !email) {
    return {
      statusCode: 400,
      headers: {
        'Access-Control-Allow-Origin': 'http://localhost:3000',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'POST',
        'Access-Control-Allow-Credentials': 'true',
      },
      body: JSON.stringify({ message: 'Username, password, and email are required' })
    };
  }
  const params = {
    TableName: 'Users',
    Key: {
      username: username
    },
  };
  try {
    const data = await dynamoDB.get(params).promise();
    // Check if the user already exists
    if (data.Item) {
      return {
        statusCode: 409, // Conflict
        headers: {
          'Access-Control-Allow-Origin': 'http://localhost:3000',
          'Access-Control-Allow-Headers': 'Content-Type',
          'Access-Control-Allow-Methods': 'POST',
          'Access-Control-Allow-Credentials': 'true',
        },
        body: JSON.stringify({ message: 'User already exists' })
      };
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const putParams = {
      TableName: 'Users',
      Item: {
        username: username,
        password: hashedPassword,
        email: email
      },
    };
    await dynamoDB.put(putParams).promise();
    return {
      statusCode: 201,
      headers: {
        'Access-Control-Allow-Origin': 'http://localhost:3000',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'POST',
        'Access-Control-Allow-Credentials': 'true',
      },
      body: JSON.stringify({ message: 'User registered successfully' })
    };
  } catch (error) {
    console.error('Error registering user:', error);
    return {
      statusCode: 500,
      headers: {
        'Access-Control-Allow-Origin': 'http://localhost:3000',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'POST',
        'Access-Control-Allow-Credentials': 'true',
      },
      body: JSON.stringify({ message: 'Error registering user', error: error.message })
    };
  }
};

//login fn
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
          'Access-Control-Allow-Origin': 'http://localhost:3000',
          'Access-Control-Allow-Headers': 'Content-Type',
          'Access-Control-Allow-Methods': 'POST',
          'Access-Control-Allow-Credentials': 'true',
        },
        body: JSON.stringify({ message: 'User not found' })
      };
    }
    const isPasswordValid = await bcrypt.compare(password, data.Item.password);
    if (!isPasswordValid) {
      return {
        statusCode: 401,
        headers: {
          'Access-Control-Allow-Origin': 'http://localhost:3000',
          'Access-Control-Allow-Headers': 'Content-Type',
          'Access-Control-Allow-Methods': 'POST',
          'Access-Control-Allow-Credentials': 'true',
        },
        body: JSON.stringify({ message: 'Invalid credentials' })
      };
    }
    const token = jwt.sign({ username: username }, SECRET_KEY, { expiresIn: '1h' });
    const expiry = new Date(Date.now() + 3 * 60 * 60 * 1000).toUTCString();
    return {
      statusCode: 200,
      headers: {
        'Access-Control-Allow-Origin': 'http://localhost:3000',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'POST',
        'Access-Control-Allow-Credentials': 'true',
        'Set-Cookie': `jwt=${token}; HttpOnly; Secure; SameSite=None; Expires=${expiry}; Path=/`, // HttpOnly cookie
      },
      body: JSON.stringify({ user: { username: data.Item.username, email: data.Item.email } })
    };
  } catch (error) {
    console.error('Error logging in:', error);
    return {
      statusCode: 500,
      headers: {
        'Access-Control-Allow-Origin': 'http://localhost:3000',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'POST',
        'Access-Control-Allow-Credentials': 'true',
      },
      body: JSON.stringify({ message: 'Error logging in', error: error.message })
    };
  }
};

//logout fn
exports.logouthandler = async (event) => {
  try {
    return {
      statusCode: 200,
      headers: {
        'Access-Control-Allow-Origin': 'http://localhost:3000',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Credentials': 'true',
        'Set-Cookie': 'jwt=; HttpOnly; Expires=Thu, 01 Jan 2000 00:00:00 GMT; SameSite=None; Secure; Path=/',
      },
      body: JSON.stringify({ message: 'Logout successful' }),
    };
  } catch (error) {
    console.error('Logout Error:', error);
    return {
      statusCode: 500,
      headers: {
        'Access-Control-Allow-Origin': 'http://localhost:3000',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Credentials': 'true',
      },
      body: JSON.stringify({ message: 'Could not log out' }),
    };
  }
};


exports.check = async (event) => {
  try {
    const validation = verifyJwtFromCookies(event);
    if (!validation.isAuthorized) {
      console.error('Token validation error:', validation.message);
      return {
        statusCode: 401,
        headers: {
          'Access-Control-Allow-Origin': 'http://localhost:3000', // Adjust as necessary
          'Access-Control-Allow-Headers': 'Content-Type, Authorization',
          'Access-Control-Allow-Methods': 'POST, OPTIONS',
          'Access-Control-Allow-Credentials': 'true',
        },
        body: JSON.stringify({ isAuthenticated: false, message: validation.message }),
      };
    }
    return {
      statusCode: 200,
      headers: {
        'Access-Control-Allow-Origin': 'http://localhost:3000', // Adjust as necessary
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Credentials': 'true',
      },
      body: JSON.stringify({
        isAuthenticated: true,
        user: {
          username: validation.user.username,
          email: validation.user.email,
        },
      }),
    };
  } catch (error) {
    console.error('Unexpected error:', error);
    return {
      statusCode: 500,
      headers: {
        'Access-Control-Allow-Origin': 'http://localhost:3000', // Adjust as necessary
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Credentials': 'true',
      },
      body: JSON.stringify({ isAuthenticated: false, message: 'Internal server error' }),
    };
  }
};


const verifyJwtFromCookies = (event) => {
  try {
    const cookieHeader = event.headers.Cookie || event.headers.cookie;
    if (!cookieHeader) {
      return { isAuthorized: false, message: 'Unauthorized: No cookies present' };
    }
    const token = cookieHeader
      .split('; ')
      .find((row) => row.startsWith('jwt='))
      ?.split('=')[1];
    if (!token) {
      return { isAuthorized: false, message: 'Unauthorized: JWT not found in cookies' };
    }
    const decoded = jwt.verify(token, SECRET_KEY);
    return { isAuthorized: true, user: decoded };
  } catch (error) {
    console.error('JWT Verification Error:', error);
    return { isAuthorized: false, message: 'Unauthorized: Invalid token' };
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
        'Access-Control-Allow-Origin': 'http://localhost:3000',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'POST',
        'Access-Control-Allow-Credentials': 'true',
      },
      body: JSON.stringify({ orderId: order.id }),
    };
  } catch (error) {
    console.error('Error creating Razorpay order:', error);
    return {
      statusCode: 500,
      headers: {
        'Access-Control-Allow-Origin': 'http://localhost:3000',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'POST',
        'Access-Control-Allow-Credentials': 'true',
      },
      body: JSON.stringify({ message: 'Error creating Razorpay order', error: error.message }),
    };
  }
};


exports.verifyPayment = async (event) => {
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature, courseId, courseName } = JSON.parse(event.body);
  
  // Verify JWT from cookies
  const jwtVerification = verifyJwtFromCookies(event);
  if (!jwtVerification.isAuthorized) {
    return {
      statusCode: 401,
      headers: {
        'Access-Control-Allow-Origin': 'http://localhost:3000',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'POST',
        'Access-Control-Allow-Credentials': 'true',
      },
      body: JSON.stringify({ message: jwtVerification.message }),
    };
  }

  const generatedSignature = crypto.createHmac('sha256', 'm4tmOl0LJmEKhmRcgvUc1xF5')
    .update(`${razorpay_order_id}|${razorpay_payment_id}`)
    .digest('hex');

  if (generatedSignature !== razorpay_signature) {
    return {
      statusCode: 400,
      headers: {
        'Access-Control-Allow-Origin': 'http://localhost:3000',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'POST',
        'Access-Control-Allow-Credentials': 'true',
      },
      body: JSON.stringify({ message: 'Invalid payment signature' }),
    };
  }

  try {
    // Fetch the course details using the courseId
    const courseParams = {
      TableName: 'SkillzephyrTable',
      Key: { courseId: courseId },
      ProjectionExpression: 'courseDetails.#n', // Only fetching the course name
      ExpressionAttributeNames: { '#n': 'name' }
    };
    const courseData = await dynamoDB.get(courseParams).promise();
    const courseName = courseData.Item.courseDetails.name;
    const validity = new Date(Date.now() + 2 * 60 * 1000).toISOString(); // Valid for 2 minutes from now


    // Update the user's profile with the purchased course details
    const params = {
      TableName: 'Users',
      Key: { username: jwtVerification.user.username }, // Use username from decoded token
      UpdateExpression: 'SET coursesPurchased = list_append(if_not_exists(coursesPurchased, :emptyList), :newCourse)',
      ExpressionAttributeValues: {
        ':emptyList': [],
        ':newCourse': [{ courseId: courseId, courseName: courseName , validity }],
      },
      ReturnValues: 'UPDATED_NEW',
    };
    const updateResult = await dynamoDB.update(params).promise();
    const presignedUrl = await generatePresignedUrl(courseId);

    return {
      statusCode: 200,
      headers: {
        'Access-Control-Allow-Origin': 'http://localhost:3000',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'POST',
        'Access-Control-Allow-Credentials': 'true',
      },
      body: JSON.stringify({ message: 'Payment verified and course added to user profile', updateResult , presignedUrl }),
    };
  } catch (error) {
    console.error('Error updating user profile after payment:', error);
    return {
      statusCode: 500,
      headers: {
        'Access-Control-Allow-Origin': 'http://localhost:3000',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'POST',
        'Access-Control-Allow-Credentials': 'true',
      },
      body: JSON.stringify({ message: 'Payment verification failed', error: error.message }),
    };
  }
};


// Function to remove expired courses for a user
exports.removeExpiredCourses = async (event) => {
  // Step 1: Extract the token from cookies and decode the username
  const { isAuthorized, user } = verifyJwtFromCookies(event);
  if (!isAuthorized) {
    return {
      statusCode: 401,
      headers: {
        'Access-Control-Allow-Origin': 'http://localhost:3000',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'POST',
        'Access-Control-Allow-Credentials': 'true',
      },
      body: JSON.stringify({ message: 'Unauthorized' }),
    };
  }

  const username = user.username;

  // Step 2: Fetch user's purchased courses from DynamoDB
  const getUserParams = {
    TableName: 'Users',
    Key: { username },
  };

  try {
    const userData = await dynamoDB.get(getUserParams).promise();

    if (!userData.Item || !userData.Item.coursesPurchased) {
      return {
        statusCode: 404,
        headers: {
          'Access-Control-Allow-Origin': 'http://localhost:3000',
          'Access-Control-Allow-Headers': 'Content-Type',
          'Access-Control-Allow-Methods': 'POST',
          'Access-Control-Allow-Credentials': 'true',
        },
        body: JSON.stringify({ message: 'User not found or no courses purchased' }),
      };
    }

    const coursesPurchased = userData.Item.coursesPurchased;

    // Step 3: Filter out expired courses
    const currentTime = Date.now();
    const updatedCourses = coursesPurchased.filter(
      (course) => new Date(course.validity).getTime() > currentTime
    );

    // Step 4: Update user's purchased courses in DynamoDB
    const updateParams = {
      TableName: 'Users',
      Key: { username },
      UpdateExpression: 'SET coursesPurchased = :updatedCourses',
      ExpressionAttributeValues: {
        ':updatedCourses': updatedCourses,
      },
      ReturnValues: 'UPDATED_NEW',
    };

    await dynamoDB.update(updateParams).promise();

    return {
      statusCode: 200,
      headers: {
        'Access-Control-Allow-Origin': 'http://localhost:3000',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'POST',
        'Access-Control-Allow-Credentials': 'true',
      },
      body: JSON.stringify({ message: 'Expired courses removed successfully' }),
    };
  } catch (error) {
    console.error('Error removing expired courses:', error);
    return {
      statusCode: 500,
      headers: {
        'Access-Control-Allow-Origin': 'http://localhost:3000',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'POST',
        'Access-Control-Allow-Credentials': 'true',
      },
      body: JSON.stringify({ message: 'Error removing expired courses', error: error.message }),
    };
  }
};