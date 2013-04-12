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

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.socket.bind(addr)
        self.lock = threading.Lock()
        self.user = None

    def serve(self):
        self.socket.listen(20)

        while True:
            cs, address = self.socket.accept()
            thread = threading.Thread(target=self.client_handler, args=(cs,))
            thread.start()

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
                    self.user = socket
                elif self.user == socket:
                    if cmd == CMD_UNLOCK:
                        self.user = None
                        self.lock.release()
                    else:
                        resp = self.handle(cmd, args)
                        pickle.dump(resp, socket_file)
                        socket_file.flush()
                else:
                    print "Command run without holding lock!"
                    break
        except Exception:
            pass
        finally:
            if self.user == socket:
                self.user = None
                self.lock.release()
            socket_file.close()
            socket.close()

    def handle(self, cmd, args):
        if cmd == CMD_WRITE:
            return self.stick.write(*args)
        elif cmd == CMD_READ:
            return self.stick.read(*args)
        elif cmd == CMD_FLUSH:
            return self.stick.flush(*args)
        elif cmd == CMD_DRAIN:
            return self.stick.drain(*args)
        print 'error: Unknown command %d' % cmd
        return 'error'


if __name__ == '__main__':
    server = YHSM_Stick_Server('/dev/ttyACM0', ('localhost', 4711))
    server.serve()
