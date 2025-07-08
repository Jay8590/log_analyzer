# Log Analyzer

A powerful, user-friendly log file analyzer built with Streamlit. This application helps you parse, filter, and analyze log files with an intuitive web interface.

## Features

- **Multi-file Support**: Upload and analyze multiple log files simultaneously
- **Real-time Filtering**: Filter logs by level, search terms, and more
- **Interactive Web Interface**: Easy-to-use web-based GUI
- **Summary Statistics**: View key metrics about your log files
- **Pagination**: Handle large log files efficiently
- **File Format Detection**: Automatically detects and validates log file formats

## Supported Log Format

⚠️ **Important**: This application only works with logs that follow a specific JSON format structure.

### Required Log Format

Each log entry must be a valid JSON object on a single line with the following structure:

```json
{
  "asctime": "2023-12-25 10:30:45,123",
  "levelname": "ERROR",
  "name": "myapp.module",
  "message": "This is a log message",
  "filename": "app.py",
  "funcName": "my_function",
  "lineno": 42
}
```

### Required Fields

- **asctime**: Timestamp in string format
- **levelname**: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- **name**: Logger name
- **message**: The actual log message
- **filename**: Source file name
- **funcName**: Function name where log was generated
- **lineno**: Line number in source file

### Example Valid Log File

```
{"asctime": "2023-12-25 10:30:45,123", "levelname": "INFO", "name": "myapp", "message": "Application started", "filename": "main.py", "funcName": "main", "lineno": 15}
{"asctime": "2023-12-25 10:30:46,456", "levelname": "DEBUG", "name": "myapp.database", "message": "Connecting to database", "filename": "db.py", "funcName": "connect", "lineno": 23}
{"asctime": "2023-12-25 10:30:47,789", "levelname": "ERROR", "name": "myapp.api", "message": "Failed to process request", "filename": "api.py", "funcName": "process_request", "lineno": 67}
```

### Supported File Extensions

- `.log`
- `.txt`
- `.log.1`, `.log.2`, etc. (rotated logs)
- `.txt.1`, `.txt.2`, etc. (rotated text logs)

---

**Note**: This application is specifically designed for structured JSON log files. Standard text-based log formats (like Apache, Nginx, or syslog) are not supported and will need to be converted to the required JSON format before analysis.
