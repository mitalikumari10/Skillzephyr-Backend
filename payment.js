const Razorpay = require('razorpay');
const crypto = require('crypto');
const aws = require('aws-sdk');
const dynamoDB = new aws.DynamoDB.DocumentClient();

// Configure Razorpay
const razorpay = new Razorpay({
  key_id: 'rzp_test_v2477Ctg5BxIwp',
  key_secret: 'm4tmOl0LJmEKhmRcgvUc1xF5 '
});



exports.createPaymentOrder = async (event) => {
    const { courseId } = JSON.parse(event.body);
  
    // Calculate amount (e.g., $100 = 10000 paise)
    const amount = 10000; // Example amount in paise
    const currency = 'INR';
  
    const options = {
      amount: amount,
      currency: currency,
      receipt: courseId,
      payment_capture: 1
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
        body: JSON.stringify({
          orderId: order.id,
          amount: order.amount,
          currency: order.currency,
          key: 'YOUR_RAZORPAY_KEY_ID'
        })
      };
    } catch (error) {
      console.error('Error creating payment order:', error);
      return {
        statusCode: 500,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Headers': 'Content-Type',
          'Access-Control-Allow-Methods': 'POST',
        },
        body: JSON.stringify({ message: 'Error creating payment order', error: error.message })
      };
    }
  };
  
  exports.verifyPayment = async (event) => {
    const { payment_id, order_id, signature } = JSON.parse(event.body);
  
    const generatedSignature = crypto.createHmac('sha256', 'YOUR_RAZORPAY_KEY_SECRET')
                                     .update(`${order_id}|${payment_id}`)
                                     .digest('hex');
  
    if (generatedSignature === signature) {
      // Handle successful payment
      return {
        statusCode: 200,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Headers': 'Content-Type',
          'Access-Control-Allow-Methods': 'POST',
        },
        body: JSON.stringify({ message: 'Payment verified successfully' })
      };
    } else {
      // Handle payment failure
      return {
        statusCode: 400,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Headers': 'Content-Type',
          'Access-Control-Allow-Methods': 'POST',
        },
        body: JSON.stringify({ message: 'Invalid payment signature' })
      };
    }
  };
  