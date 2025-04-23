import os
import psutil

def get_cpu_temperature():
    """
    Fetch the CPU temperature in Celsius.
    Returns:
        float: CPU temperature in Celsius, or "N/A" if the temperature file is not found.
    """
    # Possible paths for CPU temperature files
    temp_paths = [
        "/sys/class/thermal/thermal_zone0/temp",  # Common path for Raspberry Pi
        "/sys/class/hwmon/hwmon0/temp1_input",    # Common path for Linux systems
        "/sys/class/hwmon/hwmon1/temp1_input",    # Alternative path for Linux systems
    ]

    for path in temp_paths:
        try:
            with open(path, "r") as file:
                temp_raw = file.read().strip()
                if temp_raw.isdigit():  # Ensure the content is a valid number
                    return round(int(temp_raw) / 1000.0, 2)  # Convert from millidegrees to Celsius
        except FileNotFoundError:
            continue  # Try the next path
        except Exception as e:
            return f"Error: {str(e)}"  # Return error message for other exceptions

    return "N/A"  # Return "N/A" if no valid temperature file is found

def get_load_average():
    """
    Fetch the system load averages for the past 1, 5, and 15 minutes.
    Returns:
        tuple: A tuple containing (1-min, 5-min, 15-min) load averages.
    """
    try:
        return os.getloadavg()  # Returns (1-min, 5-min, 15-min) load averages
    except Exception as e:
        return f"Error: {str(e)}"  # Return error message if load average cannot be fetched

def get_memory_usage():
    """
    Fetch the system memory usage percentage.
    Returns:
        float: Percentage of memory used.
    """
    try:
        mem = psutil.virtual_memory()
        return round(mem.percent, 2)  # Return used memory percentage
    except Exception as e:
        return f"Error: {str(e)}"  # Return error message if memory usage cannot be fetched

def get_cpu_usage():
    """
    Fetch the system CPU usage percentage.
    Returns:
        float: Percentage of CPU used.
    """
    try:
        return round(psutil.cpu_percent(interval=1), 2)  # CPU usage percentage
    except Exception as e:
        return f"Error: {str(e)}"  # Return error message if CPU usage cannot be fetched

def get_system_stats():
    """
    Fetch and return a dictionary of system statistics.
    Returns:
        dict: A dictionary containing CPU usage, CPU temperature, memory usage, and load averages.
    """
    return {
        "cpu_usage": get_cpu_usage(),
        "cpu_temp": get_cpu_temperature(),
        "memory_usage": get_memory_usage(),
        "load_avg": get_load_average()
    }

if __name__ == "__main__":
    # Print system stats for manual testing
    print(get_system_stats())