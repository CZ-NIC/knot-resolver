import sys

from kafka.admin import KafkaAdminClient, NewTopic  # type: ignore[import-untyped]
from kafka.errors import TopicAlreadyExistsError  # type: ignore[import-untyped]

# args: create_topic.py SERVER TOPIC
server = sys.argv[1]
topic_name = sys.argv[2]

admin_client = KafkaAdminClient(bootstrap_servers=[server])


new_topic = NewTopic(name=topic_name, num_partitions=1, replication_factor=1)
try:
    admin_client.create_topics(new_topics=[new_topic], validate_only=False)
    print("Topic Created Successfully")
except TopicAlreadyExistsError as e:
    print("Topic Already Exist")
except  Exception as e:
    print(e)
