require("dotenv").config();
const mongoURI = process.env.MONGO_URI;
const MongoClient = require("mongodb").MongoClient;
const client = new MongoClient(mongoURI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const addMember = async (member) => {
  try {
    await client.connect();
    const db = client.db("notaryhash");
    const collection = db.collection("members");
    const result = await collection.insertOne(member);
    console.log(`A document was inserted with the _id: ${result.insertedId}`);
  } catch (err) {
    console.error(err);
  }
};

const getMemberByEmailAddress = async (email) => {
  try {
    await client.connect();
    const db = client.db("notaryhash");
    const collection = db.collection("members");
    const result = await collection.findOne({ email: emailAddress });
    console.log(result);
    return result;
  } catch (err) {
    console.error(err);
  }
};
const getMembers = async () => {
  try {
    await client.connect();
    const db = client.db("notaryhash");
    const collection = db.collection("members");
    const result = await collection.find({}).toArray();
    console.log(result);
  } catch (err) {
    console.error(err);
  }
};

const addReferral = async (referral) => {
  try {
    await client.connect();
    const db = client.db("notaryhash");
    const collection = db.collection("referrals");
    const result = await collection.insertOne(referral);
    console.log(`A document was inserted with the _id: ${result.insertedId}`);
  } catch (err) {
    console.error(err);
  }
};
// update referral as claimed
const updateReferral = async (referral) => {
  try {
    await client.connect();
    const db = client.db("notaryhash");
    const collection = db.collection("referrals");
    const result = await collection.updateOne(
      { referralCode: referral.referralCode },
      { $set: { claimed: true } }
    );
    console.log(`A document was inserted with the _id: ${result.insertedId}`);
  } catch (err) {
    console.error(err);
  }
};

const getReferrals = async () => {
  try {
    await client.connect();
    const db = client.db("notaryhash");
    const collection = db.collection("referrals");
    const result = await collection.find({}).toArray();
    console.log(result);
  } catch (err) {
    console.error(err);
  }
};

const addTransaction = async (transaction) => {
  try {
    await client.connect();
    const db = client.db("notaryhash");
    const collection = db.collection("transactions");
    const result = await collection.insertOne(transaction);
    console.log(`A document was inserted with the _id: ${result.insertedId}`);
  } catch (err) {
    console.error(err);
  }
};

const getTransactions = async () => {
  try {
    await client.connect();
    const db = client.db("notaryhash");
    const collection = db.collection("transactions");
    const result = await collection.find({}).toArray();
    console.log(result);
  } catch (err) {
    console.error(err);
  }
};

module.exports = {
  addMember,
  getMemberByEmailAddress,
  getMembers,
  addReferral,
  updateReferral,
  getReferrals,
  addTransaction,
  getTransactions,
};
