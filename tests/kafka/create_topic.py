import sys

from kafka.admin import KafkaAdminClient, NewTopic  # type: ignore[import-untyped]
from kafka.errors import TopicAlreadyExistsError  # type: ignore[import-untyped]

server = sys.argv[1]
topic = NewTopic(name=sys.argv[2], num_partitions=1, replication_factor=1)

# create topic if not exists
admin_client = KafkaAdminClient(bootstrap_servers=[server], client_id="client-test")
try:
    print(admin_client.describe_cluster())
    admin_client.create_topics(new_topics=[topic], validate_only=False)
    print(f"Topic {topic.name} created Successfully")
    admin_client.close()
except TopicAlreadyExistsError:
    print(f"Topic '{topic.name}' already exist")
