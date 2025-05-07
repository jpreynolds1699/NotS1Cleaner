import csv
from datetime import datetime, timedelta

def parse_duration(duration_str):
    """Convert duration string format HH:MM:SS into timedelta."""
    h, m, s = map(int, duration_str.strip().split(":"))
    return timedelta(hours=h, minutes=m, seconds=s)

def get_max_simultaneous_calls(csv_file_path):
    events = []

    with open(csv_file_path, newline='') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            # Skip empty or malformed rows
            if len(row) < 6:
                continue

            timestamp_str = row[0]
            status = row[3].strip().lower()
            ring_duration = row[4].strip()
            talk_duration = row[5].strip()

            # Skip non-answered or zero-duration calls
            if status != 'answered' or talk_duration == "00:00:00":
                continue

            try:
                start_time = datetime.fromisoformat(timestamp_str)
                duration = parse_duration(talk_duration)
                end_time = start_time + duration
            except ValueError:
                continue  # Skip rows with invalid date or duration

            # Create a +1 event at start and a -1 event at end
            events.append((start_time, 1))
            events.append((end_time, -1))

    # Sort events chronologically, breaking ties by ending (-1) before starting (+1)
    events.sort()

    max_calls = 0
    current_calls = 0

    for event_time, change in events:
        current_calls += change
        max_calls = max(max_calls, current_calls)

    return max_calls


csv_path = "C:/Users/JamesReynolds/Downloads/call_report_wd.csv"
max_concurrent = get_max_simultaneous_calls(csv_path)
print("Maximum simultaneous calls:", max_concurrent)