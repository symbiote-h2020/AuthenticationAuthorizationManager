//Mongo scripts migrating database from AAM version 2.0.+ to 3.0.2
//script should be properly updated, according to database settings, and run from mongo shell

//CONNECTION TO DB - fill DB name and link
conn = new Mongo();
db = conn.getDB("symbiote-aam-database");
//OR USING PROPER LINK TO DB     db = connect("localhost:27020/DATABASE_NAME");

//DO NOT CHANGE THOSE TWO LINES
db.user.updateMany({}, {$rename: {"ownedPlatforms": "ownedServices"}})
db.user.updateMany({role: "PLATFORM_OWNER"}, {$set: {role: "SERVICE_OWNER"}})