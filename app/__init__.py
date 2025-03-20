from datetime import datetime

@app.template_filter('datetime')
def format_datetime(value):
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace('Z', '+00:00'))
    return value.strftime('%Y-%m-%d %H:%M:%S') 