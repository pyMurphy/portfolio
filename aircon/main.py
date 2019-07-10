# import packet
# import raw
import pyshark
import socket
from sys import exit

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
# s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

# TERMINAL COLOURS

class colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# STARTUP TEXT

def startup():
    print(f'''{colors.OKBLUE}


 ▄▄▄       ██▓ ██▀███   ▄████▄   ▒█████   ███▄    █ 
▒████▄    ▓██▒▓██ ▒ ██▒▒██▀ ▀█  ▒██▒  ██▒ ██ ▀█   █ 
▒██  ▀█▄  ▒██▒▓██ ░▄█ ▒▒▓█    ▄ ▒██░  ██▒▓██  ▀█ ██▒
░██▄▄▄▄██ ░██░▒██▀▀█▄  ▒▓▓▄ ▄██▒▒██   ██░▓██▒  ▐▌██▒
 ▓█   ▓██▒░██░░██▓ ▒██▒▒ ▓███▀ ░░ ████▓▒░▒██░   ▓██░
 ▒▒   ▓▒█░░▓  ░ ▒▓ ░▒▓░░ ░▒ ▒  ░░ ▒░▒░▒░ ░ ▒░   ▒ ▒ 
  ▒   ▒▒ ░ ▒ ░  ░▒ ░ ▒░  ░  ▒     ░ ▒ ▒░ ░ ░░   ░ ▒░
  ░   ▒    ▒ ░  ░░   ░ ░        ░ ░ ░ ▒     ░   ░ ░ 
      ░  ░ ░     ░     ░ ░          ░ ░           ░ 
                       ░      

Type 'help' for a list of commands...\n
{colors.ENDC}''')

# TERMINAL CLASS TO HANDLE INPUT FROM USER

class terminal:
    def __init__(self):
        self.history=[]
        self.state='air'
        self.color=colors.OKBLUE
        self.help=[
            ['help','Shows a list of commands'],
            ['exit','Closes the current interface'],
            ['craft','Opens interface to craft your own packets\n'],
            [' -- edit','Edits the packet to be sent'],
            [' -- send','Sends the packet'],
            ['\nlisten','Opens interface for monitoring packets\n'],
            [' -- start','Starts listening. To stop, press CTRL+C'],
            ['\nback','Closes any interface and goes back to the main interface']
        ]
    def send(self, cmd):
        self.history.append(cmd)
        args = cmd.split()
        commands = {
            'exit':lambda:exit(0),
            'help':lambda:print('\n'+'\n'.join([x[0]+':\t'+x[1] for x in self.help]),'\n'),
            'craft':lambda:self.change_state('craft'),
            'listen':lambda:self.change_state('listen'),
            'back':lambda:self.change_state('air')
        }
        craft_commands = {
            'edit':lambda:print('edit'),
            'send':lambda:print('send')
        }
        listen_commands = {
            'start':lambda:self.listen()
        }
        try:
            cmd = args[0].lower()
            if cmd in commands:
                commands[cmd]()
            elif self.state == 'craft' and cmd in craft_commands:
                craft_commands[cmd]()
            elif self.state == 'listen' and cmd in listen_commands:
                listen_commands[cmd]()
        except Exception as e:
            self.warn(f'An unexpected error occured: {e}')
    def change_state(self,name):
        states={
            'air':colors.OKBLUE,
            'craft':colors.OKGREEN,
            'listen':colors.FAIL
        }
        self.state=name
        self.color=states[name]
    def listen(self):
        try:
            capture = pyshark.LiveCapture(interface='any')
            self.warn('Listening... Press CTRL+C to stop.')
            capture.sniff()
        except KeyboardInterrupt as e:
            self.warn('\nStopping...')
        print(f'{len(capture)} packets captured')
    def warn(self,text):
        print(f'{colors.FAIL}{text}{colors.ENDC}')

def main():
    console = terminal()
    while True:
        command=input(f'({console.color}{console.state}{colors.ENDC}) ')
        console.send(command)
        

if __name__ == '__main__':
    startup()
    main()