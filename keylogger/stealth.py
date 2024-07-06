import os

def hide_file(file_path):
    """
    Hide a file (Windows only).
    """
    os.system(f"attrib +h {file_path}")

def run_in_background(script_path):
    """
    Run the script in the background.
    """
    if os.name == 'nt':
        os.system(f"start /B python {script_path}")
    else:
        os.system(f"nohup python {script_path} &")
