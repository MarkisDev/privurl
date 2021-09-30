import json
import pymongo
from datetime import datetime
# Fetching DB details
with open('config.json') as f:
    MONGODB_AUTH = json.load(f)

# Initializing database client 
db_client = pymongo.MongoClient(MONGODB_AUTH['connection'])
# Selecting database
db = db_client[MONGODB_AUTH['db_name']]

# Deleting all the entries in the database which are 12 hours old (not the most efficient way, but it's okay for now)
data = db['data'].find({}, {'_id':0})
for entry in data:
    time_now = datetime.utcnow()
    time_then = entry['timestamp']
    time_diff = time_now - time_then
    diff_in_seconds = time_diff.total_seconds()
    if diff_in_seconds < 12 * 3600:
        db['data'].delete_one({'unique':entry['unique']})
        print('Deleted:' + entry['unique'])

# Updating the reset timer in the db
db['admin'].update_one({'name':'reset_timestamp'}, {'$set':{'key': datetime.utcnow(), 'name':'reset_timestamp'}})