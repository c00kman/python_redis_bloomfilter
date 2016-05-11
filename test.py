import redis
import csv
from pybloom.pybloom import BloomFilter

redis_client = redis.StrictRedis(host='192.168.192.12', port=6381, db=2)
filter_key = 'test'
redis_client.delete(filter_key)


bf = BloomFilter(redis_client, filter_key, 100000000, 0.0000001)

id = '1000'
if not bf.contain(id):
    bf.add(id)
else:
    print("already in")
