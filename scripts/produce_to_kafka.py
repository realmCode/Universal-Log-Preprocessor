"""
Kafka Producer — reads log files and produces to a Kafka topic.
Used by the log generator service in Docker Compose.
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from kafka import KafkaProducer
except ImportError:
    print("kafka-python not installed. Run: pip install kafka-python")
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Produce logs to Kafka")
    parser.add_argument("--input", "-i", required=True, help="Input log file")
    parser.add_argument("--topic", "-t", default="raw_logs", help="Kafka topic")
    parser.add_argument("--broker", "-b", default="localhost:9092", help="Kafka broker")
    args = parser.parse_args()

    producer = KafkaProducer(
        bootstrap_servers=args.broker,
        value_serializer=lambda v: v.encode("utf-8"),
    )

    print(f"Producing from {args.input} to topic {args.topic}...")
    with open(args.input, "r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if line:
                producer.send(args.topic, line)
            if (i + 1) % 100 == 0:
                print(f"  Sent {i+1} messages...")

    producer.flush()
    print(f"Done. Produced all messages.")


if __name__ == "__main__":
    main()
