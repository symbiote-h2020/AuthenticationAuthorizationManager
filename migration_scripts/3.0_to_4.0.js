//Mongo scripts migrating database from AAM version 2.0.+ to 3.0.2
//script should be properly updated, according to database settings, and run from mongo shell

//CONNECTION TO DB - fill DB name and link
conn = new Mongo();
db = conn.getDB("DATABASE_NAME");
//OR USING PROPER LINK TO DB     db = connect("localhost:27020/DATABASE_NAME");

//DO NOT CHANGE THOSE LINES
db.user.updateMany({}, {$set: {status: "NEW", serviceConsent: false, marketingConsent: false}})