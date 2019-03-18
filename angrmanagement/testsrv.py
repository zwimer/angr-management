import zmq
import angr_comm_pb2
from queue import Queue
import time


##### SERVER #####

topic_poi = b'poi'
topic_sync = b'sync'
srv_port = 40001
pub_context = zmq.Context()
srv_socket = pub_context.socket(zmq.REP)
srv_socket.bind("tcp://*:{}".format(srv_port))

all_pois = {}  # key is user, value is set() of POIs


def do_srv_loop():
    global all_pois
    while True:
        msg = srv_socket.recv()
        if msg[0:3] == b'get':
            srv_socket.send('all my pois')
        elif msg[0:3] == b'set':
            print("Got new POIs")
            poi_list = angr_comm_pb2.ActyList()
            poi_list.ParseFromString(msg[3:])
            for poi in poi_list.pois:
                src = None
                try:
                    src = all_pois[poi.source]
                except KeyError:
                    all_pois[poi.source] = list()
                    src = all_pois[poi.source]

                if src is None:
                    raise Exception("Failed to find/create POI source!")

                src.append(poi)
        srv_socket.send(b'ack')


##### USER #####
srv_ip = "127.0.0.1"
sub_context = zmq.Context()
sub_socket = sub_context.socket(zmq.REQ)
sub_socket.connect("tcp://{}:{}".format(srv_ip, srv_port))

def do_clt_loop(user):
    def get_local_pois():
        poi_msg = angr_comm_pb2.ActyList()
        for addr in [0x0040085a, 0x0040085a, 0x0040085a]:
            msg = poi_msg.user_activity.add()
            msg.tool = 'angr-management'
            msg.timestamp = int(time.time())
            msg.source = 'user{}'.format(user)
            msg.file = 'TEST_BINARY_NAME'  # testlib/test_preload
            msg.code_location = addr
            msg.loc_type = angr_comm_pb2.UserActy.INST_ADDR
        return poi_msg

    pm = get_local_pois()
    sub_socket.send(b'set' + pm.SerializeToString())
    ack = sub_socket.recv()
    if ack != b'ack':
        print("Got unknown response. Expected server 'ack'")


def launch():
    from threading import Thread
    srv_thread = Thread(target=do_srv_loop)
    srv_thread.start()

    for i in range(1,8):
        do_clt_loop(i)

launch()
print("Server has POIs from {} users".format(len(all_pois)))

#######################################################################################################################
#######################################################################################################################

def test_pub_sub():
    msg = angr_comm_pb2.UserActy()
    msg.tool = 'angr-management'
    msg.timestamp = int(time.time())
    msg.source = 'TEST_REMOTE_SOURCE'
    msg.file = 'TEST_BINARY_NAME'  # testlib/test_preload
    msg.code_location = 0x0040085a
    msg.loc_type = angr_comm_pb2.UserActy.INST_ADDR

    import zmq
    topic_poi = b'poi'
    poi_pub_srv = '127.0.0.1'
    poi_pub_port = 44444

    pub_context = zmq.Context()
    pub_socket = pub_context.socket(zmq.PUB)
    pub_socket.bind("tcp://*:{}".format(poi_pub_port))
    time.sleep(1)


    sub_context = zmq.Context()
    sub_socket = sub_context.socket(zmq.SUB)
    sub_socket.connect("tcp://{}:{}".format(poi_pub_srv, poi_pub_port))
    sub_socket.setsockopt(zmq.SUBSCRIBE, topic_poi)
    time.sleep(3)

    #while True:
    for i in range(0, 3):
        pub_socket.send(topic_poi + b' ' + msg.SerializeToString())
        time.sleep(1)

        topic_and_data = sub_socket.recv()
        topic, data = topic_and_data.split(b' ', 1)
        if topic == topic_poi:
            msg = angr_comm_pb2.UserActy()
            msg.ParseFromString(data)
            print("Got new message: {}".format(msg))
