require("dotenv").config();
const nodemailer = require("nodemailer");

// Create a transporter using PrivateEmail.com's SMTP settings
let transporter = nodemailer.createTransport({
  host: "mail.privateemail.com",
  port: 587, // or 465 if using SSL
  secure: false, // true for 465, false for other ports
  auth: {
    user: "support@notaryhash.com", // Your full email address
    pass: process.env.EMAIL_PASSWORD, // Your password from environment variable
  },
});

/**
 * Send 2FA code via email.
 * @param {string} recipientEmail - The email address of the recipient.
 * @param {string} code - The 2FA code to send.
 */
function send2FACode(recipientEmail, code) {
  let mailOptions = {
    from: "support@notaryhash.com",
    to: recipientEmail,
    subject: "2FA Code",
    text: `Your 2FA code is: ${code}`,
  };

  transporter.sendMail(mailOptions, function (error, info) {
    if (error) {
      console.log(error);
    } else {
      console.log("Email sent: " + info.response);
    }
  });
}

// Example usage
// send2FACode("recipient@example.com", "123456");

module.exports = {
  send2FACode,
};
