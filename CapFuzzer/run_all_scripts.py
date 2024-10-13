import subprocess
import sys
def run_script(script_name,script_param):
    try:
        result = subprocess.run(['python3', script_name,script_param], check=True, capture_output=True, text=True)
        print(f"Output of {script_name}:\n{result.stdout}")
    except subprocess.CalledProcessError as e:
        print(f"Error running {script_name}:\n{e.stderr}")
        raise


if __name__ == "__main__":
    if len(sys.argv) != 2:
            print("Usage: python run_all_scripts.py <input_file>")
            sys.exit(1)
    input_file = sys.argv[1]
    scripts = ['1_getmanuals.py', '2_getoptfromlib.py', '3_parse.py', '4_fuzzcmd.py','5_runfuzzcmds.py']
    for script in scripts:
        run_script(script,input_file)
