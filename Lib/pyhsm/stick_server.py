import sys
import socket
import pickle
import threading

import pyhsm.stick


CMD_WRITE = 0
CMD_READ = 1
CMD_FLUSH = 2
CMD_DRAIN = 3
CMD_LOCK = 4
CMD_UNLOCK = 5


class YHSM_Stick_Server():
    def __init__(self, device, addr, **kwargs):
        self.stick = pyhsm.stick.YHSM_Stick(device, **kwargs)

        self.commands = {
            CMD_WRITE: self.stick.write,
            CMD_READ: self.stick.read,
            CMD_FLUSH: self.stick.flush,
            CMD_DRAIN: self.stick.drain,
        }

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.socket.bind(addr)
        self.lock = threading.RLock()

    def serve(self):
        self.socket.listen(20)

        try:
            while True:
                cs, address = self.socket.accept()
                thread = threading.Thread(target=self.client_handler,
                                          args=(cs,))
                thread.start()
        except:
            sys.exit(1)

    def client_handler(self, socket):
        socket_file = socket.makefile('wb')

        try:
            while True:
                data = pickle.load(socket_file)
                cmd = data[0]
                args = data[1:]
                if cmd == CMD_LOCK:
                    self.lock.acquire()
                elif self.lock.acquire(blocking=False):
                    try:
                        if cmd == CMD_UNLOCK:
                            self.lock.release()
                        else:
                            pickle.dump(self.commands[cmd](*args), socket_file)
                            socket_file.flush()
                    finally:
                        self.lock.release()
                else:
                    print "Command run without holding lock!"
                    break
        except Exception:
            pass
        finally:
            try:
                self.lock.release()
            except:
                pass
            socket_file.close()
            socket.close()


if __name__ == '__main__':
    server = YHSM_Stick_Server('/dev/ttyACM0', ('localhost', 4711))
    server.serve()
