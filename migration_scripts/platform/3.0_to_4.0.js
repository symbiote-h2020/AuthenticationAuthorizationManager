//Mongo scripts migrating database from AAM version 3.0.+ to 4+
//script should be properly updated, according to database settings, and run from mongo shell

//CONNECTION TO DB - fill DB name and link
conn = new Mongo();
db = conn.getDB("symbiote-aam-database");
//OR USING PROPER LINK TO DB     db = connect("localhost:27020/DATABASE_NAME");

//DO NOT CHANGE THOSE LINES
db.user.updateMany({}, {$set: {status: "ACTIVE", serviceConsent: true, analyticsAndResearchConsent: false}})