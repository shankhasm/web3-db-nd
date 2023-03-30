import subprocess
import os
import threading
import time

THREADS_REPO = """C:/Users/Jake Chandler/WebstormProjects/go-threads/"""
THREAD_DB = """./threadsd/"""
WEB3DB_REPO = "./web3db/"
MAIN = "./src/main.go"



def install_thread_requirements() -> int:
    go_command = 'go'
    go_args = 'get'
    ret = subprocess.call([go_command, go_args, THREAD_DB])
    return ret


def run_thread_db() -> None:
    go_command = 'go'
    go_args = 'run'
    subprocess.call([go_command, go_args, THREAD_DB])
    
class ThreadDB(threading.Thread):
    def __init__(self):
        super().__init__()

    def run(self):
        os.chdir(THREADS_REPO)
        install_thread_requirements()
        run_thread_db()


def run_web3_db() -> int:
    go_command = 'go'
    go_args = 'run'
    print(os.getcwd())
    return subprocess.call([go_command, go_args, MAIN])

class Web3DB(threading.Thread):
    def __init__(self, web3_db_uga_repo: str):
        super().__init__()
        self.web3_db_uga_repo = web3_db_uga_repo
        print(self.web3_db_uga_repo)


    def run(self):
        os.chdir(self.web3_db_uga_repo + WEB3DB_REPO)
        
        # install_web3db_requirements()
        run_web3_db()
        

class Web3DBAdmin(Web3DB):
    def run(self):
        os.chdir(self.web3_db_uga_repo)

if __name__ == '__main__':
    web3_db_uga_repo = os.getcwd()
    threadDb = ThreadDB()
    web3db = Web3DB(web3_db_uga_repo )
    print("================ STARTING THREAD DB ================")
    threadDb.start()
    
    # give some time for Thread DB to start
    time.sleep(15)
    
    print("================ STARTING WEB3 DB ================")
    web3db.start()
    web3db.join()
    
    
    

    
