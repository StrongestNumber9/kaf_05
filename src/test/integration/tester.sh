#!/bin/bash
echo "Starting kafka";
su - srv-kaf_07 -s "$(which bash)" -c 'KAFKA_OPTS="-Djava.security.auth.login.config=/config/kafka.jaas.conf" CLASSPATH=/opt/teragrep/kaf_05/share/kaf_05.jar /opt/teragrep/kaf_06/bin/kafka-server-start.sh -daemon /config/kafka.properties'

echo "Sleeping a bit to let it wake up";
sleep 5;

for i in {1..10}; do
    echo "Attempt ${i} of seeing if kafka is up";
    if nc -z 127.0.0.1 9092; then
        break;
    fi;
    if [ "${i}" -eq "10" ]; then
        echo "Could not connect to kafka, failing. Printing last 50 lines of logs:";
        tail -50 /opt/teragrep/kaf_06/logs/kafkaServer.out;
        exit 1;
    fi;
    sleep 1;
done;

# Create a topic and write to it
echo "Creating some logs by creating and writing to a new topic"
KAFKA_OPTS="-Djava.security.auth.login.config=/config/cluster.jaas.conf" /opt/teragrep/kaf_06/bin/kafka-topics.sh --create --topic test-topic --partitions 1 --replication-factor 1 --bootstrap-server 127.0.0.1:9092 --command-config /config/producer.properties

echo "Writing to the topic";
KAFKA_OPTS="-Djava.security.auth.login.config=/config/writer.jaas.conf" /opt/teragrep/kaf_06/bin/kafka-console-producer.sh --topic test-topic --producer-property sasl.mechanism=PLAIN --producer-property security.protocol=SASL_PLAINTEXT --broker-list 127.0.0.1:9092 <<< "test-message";

function grep_message() {
    echo "Grepping '${1}' from /opt/teragrep/kaf_06/logs/kafkaServer.out";
    if ! grep "${1}" /opt/teragrep/kaf_06/logs/kafkaServer.out; then
        echo "Can't find '${1}' from logs, failing";
        exit 1;
    fi;
}

echo "Checking if all messages are as expected in kafkaServer.out";
grep_message "TeragrepAuthenticateCallbackHandler initialized";
grep_message "Didn't find property <\[credentials.file\]>";
grep_message "Didn't find property <\[writer.file\]>";
grep_message "Didn't find property <\[cluster.file\]>";
grep_message "Didn't find property <\[identitySuffix.file\]>";

echo "Adding properties and restarting server";
kill -TERM "$(ps ax | grep -i 'kafka\.Kafka' | grep java | awk '{print $1}')";

for role in broker controller; do
    sed -i '/^listener.name.'${role}'.plain.sasl.jaas.config/d' /config/kafka.properties
    echo 'listener.name.'${role}'.plain.sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required username="kafka" password="kafka" user_kafka="kafka" user_writer="writer" credentials.file="/config/credentials.json" cluster.file="/config/credentials.cluster.json" writer.file="/config/credentials.writer.json" identitySuffix.file="/config/identitySuffix.json";'  >> /config/kafka.properties
done;

# Just because permissions and clean shutdown is not possible right now
sleep 30;

echo "Starting kafka";
su - srv-kaf_07 -s "$(which bash)" -c 'KAFKA_OPTS="-Djava.security.auth.login.config=/config/kafka.jaas.conf" CLASSPATH=/opt/teragrep/kaf_05/share/kaf_05.jar /opt/teragrep/kaf_06/bin/kafka-server-start.sh -daemon /config/kafka.properties'

echo "Sleeping a bit to let it recover";
sleep 2;

echo "Checking if all messages are as expected in kafkaServer.out";
grep_message "Resolved property <\[credentials.file\]> to";
grep_message "Resolved property <\[writer.file\]> to";
grep_message "Resolved property <\[cluster.file\]> to";
grep_message "Resolved property <\[identitySuffix.file\]> to";
