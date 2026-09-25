"""ID generation utilities."""
import uuid


def generate_event_id() -> str:
    """Generate a unique event ID (UUID4)."""
    return str(uuid.uuid4())
