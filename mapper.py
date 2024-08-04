from os import path
from tqdm import tqdm
from time import sleep
from requests import get
from scp import SCPClient
from datetime import datetime
from folium import Map, Circle
from paramiko import SSHClient, AutoAddPolicy


def get_file(hostname, username, password, sudo_password, key_filename=None):
    try:
        ssh = SSHClient()

        ssh.set_missing_host_key_policy(AutoAddPolicy())
        ssh.connect(hostname=hostname, username=username, password=password, key_filename=key_filename)

        stdin, _, _ = ssh.exec_command('sudo -S cp /var/log/auth.log .')
        stdin.write(f'{sudo_password}\n')
        stdin.flush()

        stdin, _, _ = ssh.exec_command('sudo -S chmod 666 auth.log')
        stdin.write(f'{sudo_password}\n')
        stdin.flush()

        scp = SCPClient(ssh.get_transport())

        scp.get('auth.log', '.')
        ssh.close()
    except Exception as e:
        print(e)
        exit(0)

def analyze_authlog(auth_path):
    events = {}
    actions = {}
    hostnames = []
    valid_logons = {}
    invalid_logons = {}
    password_runs = {}

    with open(auth_path, 'r') as logs:
        for log in logs.readlines():

            log = ' '.join(log.split())

            month = log.split(' ')[0]
            day   = log.split(' ')[1]
            hour  = log.split(' ')[2]

            date = datetime.strptime(f"{datetime.now().date().strftime("%Y")} {month} {day} {hour}", "%Y %b %d %H:%M:%S")
            hostname = log.replace(f"{month} {day} {hour}", "").lstrip().split(' ')[0]
            servorproc = log.replace(f"{month} {day} {hour}", "").lstrip().split(' ')[1]
            event = log.replace(f"{month} {day} {hour} {hostname} {servorproc}", "").rstrip()

            if hostname not in hostnames:
                hostnames.append(hostname)

            events[date] = {'Server/Process': servorproc, "Event": event}

            if 'sshd' in servorproc and 'Invalid user' in event:
                ip = event.split('from')[-1].split('port')[0].strip()
                if ip in invalid_logons:
                    invalid_logons[ip].append(event.strip())
                else:
                    invalid_logons[ip] = [event.strip()]

            elif 'sshd' in servorproc and 'Accepted publickey' in event or 'Accepted password' in event:
                ip = event.split('from')[-1].split('port')[0].strip()
                if ip in valid_logons:
                    valid_logons[ip].append(event.strip())
                else:
                    valid_logons[ip] = [event.strip()]

            if 'pam_unix' in event and 'session opened' in event:
                user = event.strip()[9:len(event)].split(':')[0]
                if user in password_runs:
                    password_runs[user].append(date)
                else:
                    password_runs[user] = [date]

            if 'COMMAND=' in event:
                terminal = None
                working_directory = None
                invoked_user = None
                command = None
                    
                invoking_user = event.split(':')[0].strip()

                if 'TTY' in event:
                    terminal = event.split('TTY=')[1].split(';')[0].strip()

                if 'PWD' in event:
                    working_directory = event.split('PWD=')[1].split(';')[0].strip()

                if 'USER' in event:
                    invoked_user = event.split('USER=')[1].split(';')[0].strip()

                if 'COMMAND' in event:
                    command = event.split('COMMAND=')[1].strip()

                if servorproc in actions:
                    actions[servorproc].append({"Date": date, "Invoking user": invoking_user, "Terminal": terminal, "Working directory": working_directory, "Invoked user": invoked_user, "Command": command})
                else:
                    actions[servorproc] = [{"Date": date, "Invoking user": invoking_user, "Terminal": terminal, "Working directory": working_directory, "Invoked user": invoked_user, "Command": command}]

    return {"Events": events, "Actions": actions, "Hostnames": hostnames, "Valid logons": valid_logons, "Invalid logons": invalid_logons, "Password runs": password_runs}


def create_heatmap(auth_data, data_source):
    geo_data = []
    for ip in list(auth_data.get(data_source).keys()):
        geo_data.append([ip, len(auth_data.get(data_source)[ip]), {}])

    for i in tqdm(range(len(geo_data))):
        response = get(f'https://ipapi.co/{geo_data[i][0]}/json/').json()
        
        city = response.get('city')
        region = response.get('region')
        organization = response.get('org')
        latitude = response.get('latitude')
        longitude = response.get('longitude')
        utc_offset = response.get('utc_offset')
        country_name = response.get('country_name')

        geo_data[i][2] = {'City': city, 'region': region, 'latitude': latitude, 'longitude': longitude, 'UTC offset': utc_offset, 'Country name': country_name, 'Organization': organization}
        sleep(1)

    map = Map(location=[30,0], zoom_start=2)

    for ip, connection_number, details in geo_data:
        latitude = details['latitude']
        longitude = details['longitude']

        Circle(location=[latitude, longitude], radius=connection_number*500, color='red', fill=True, fill_color='red', 
               popup=f"IP: \n{ip}\nConnections: \n{connection_number}\nCity: \n{details['City']}\nCountry: \n{details['Country name']}\nOrganization: \n{details['Organization']}").add_to(map)
        
    map.save('heatmap.html')

def main():
    print('''
        [1] Download auth.log using SCP
        [2] Analyze existing auth.log file
        [3] Exit
    ''')

    try:
        choice = int(input("Your choice: "))

        if choice != 1 and choice != 2:
            print("Invalid input exiting...")
            exit(0)
        if choice == 3:
            print("Exiting...")
            exit(0)
    
    except Exception:
        print("Invalid input exiting...")
        exit(0)

    auth_data = {}

    if choice == 1:
        hostname = input("hostname: ")
        username = input("username: ")
        password = input("password: ")
        sudo_password = input("sudo password: ")

        key_file = input("path to keyfile (enter to skip): ")

        if not path.exists(key_file):
            print("Key file not found exiting...")
            exit(0)

        get_file(hostname, username, password, sudo_password, key_file)
        auth_data = analyze_authlog('.\\auth.log')

    else:
        auth_path = input("auth.log path (defaults to current directory): ")

        if auth_path == "":
            auth_path = ".\\auth.log"

        if not path.exists(auth_path):
            print("auth.log file not found exiting...")
            exit(0)

        auth_data = analyze_authlog(auth_path)

    print('''
        [1] Display all invalid connection attempts
        [2] Create world heatmap of invalid connecitons attempts
        [3] Display all valid connection attempts (user only)
        [4] Create world heatmap of valid connection attempts
        [5] Display list of commands run on the machine
        [6] Display all valid connection attempts (system processes included)
        [7] Exit
    ''')

    try:
        choice = int(input("Your choice: "))

        if not 0 < choice < 7:
            print("Invalid input exiting...")
            exit(0)
        if choice == 7:
            print("Exiting...")
            exit(0)
    
    except Exception:
        print("Invalid input exiting...")
        exit(0)

    if choice == 2 or choice == 4:
        data_source = (lambda: "Invalid logons" if choice == 2 else "Valid logons")()
        create_heatmap(auth_data, data_source)

    if choice == 1 or choice == 3 or choice > 4:
        print('''
            [1] Print to screen
            [2] Print to file
        ''')

        data_source = (lambda: "Invalid logons" if choice == 1 else (lambda: "Valid logons" if choice == 3 else (lambda: "Actions" if choice == 5 else "Password runs")())())()

        try:
            print_choice = int(input("Your choice: "))

            if print_choice != 1 and print_choice != 2:
                print("Invalid input exiting...")
                exit(0)
    
        except Exception:
            print("Invalid input exiting...")
            exit(0)

        login_data = []
        for content in auth_data.get(data_source).keys():
            for event in auth_data.get(data_source).get(content):
                if choice == 5:
                    login_data.append(f"{event.get("Invoking user")} {event.get("Working directory")}: {event.get("Command")}")
                elif choice == 6:
                    login_data.append(f"{content} connected {len(auth_data.get(data_source).get(content))} times")
                    break
                else:
                    login_data.append(event)
        if print_choice == 1:
            for event in login_data:
                print(event)
        else:
            with open(f"{data_source}.txt", "w") as logons:
                for event in login_data:
                    logons.write(f"{event}\n")

if __name__ == '__main__':
    main()
