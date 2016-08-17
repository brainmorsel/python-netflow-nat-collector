#!/usr/bin/env python

import time
import asyncio
import ipaddress
import queue
import threading
import io
import logging

import click
import psycopg2

from . import util
from . import nf
from . import pcap


class StorePgThreadPool:
    class Worker(threading.Thread):
        def __init__(self, requests, dsn):
            threading.Thread.__init__(self)
            self.requests = requests

            self.db_conn = psycopg2.connect(**dsn)

            self.setDaemon(True)
            self.start()

        def run(self):
            while True:
                records = self.requests.get()
                data = '\n'.join(
                    ['\t'.join(
                        [str(i) for i in rec]
                    ) for rec in records]
                )
                f = io.StringIO(data)
                cur = self.db_conn.cursor()
                cur.copy_from(
                    f, 'nfcollect.log_items',
                    columns=('event_time', 'src_addr', 'dst_addr', 'dst_port', 'xlate_src_addr', 'xlate_src_port', 'protocol'))
                self.db_conn.commit()
                cur.close()
                self.requests.task_done()
                logging.info('StorePgThreadPool: data batch commited to db')

    def __init__(self, num_threads, db_conn_str):
        self.requests = queue.Queue(num_threads)
        for _ in range(num_threads):
            self.Worker(self.requests, db_conn_str)

    def addRequest(self, records_buf):
        self.requests.put(records_buf)

    def waitCompletion(self): self.requests.join()

    def getQueueSize(self):
        return self.requests.qsize()


class MirrorProtocol:
    def __init__(self, target=None):
        self._target = target

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, buffer, addr):
        self._target.transport.sendto(buffer)

    def error_received(self, exc):
        print('mirror: Error received:', exc)

    def connection_lost(self, exc):
        print("mirror: Socket closed")

    def report_stats(self, seconds):
        pass


class PgNelStoreProtocol:
    def __init__(self, dsn, workers=1, buffer_size=1000):
        self.nf_parser = nf.Parser(version=9)
        self.workers_pool = StorePgThreadPool(workers, dsn)
        self.buffer = []
        self.buffer_size = buffer_size
        self._stat_dgrams = 0
        self._stat_flowsets = 0

    def datagram_received(self, buffer, addr):
        self._stat_dgrams += 1
        for pkt_header, flow_set in self.nf_parser.parse(buffer, addr):
            self._stat_flowsets += 1
            self._handle_flow_set(addr, pkt_header, flow_set)

    def _handle_flow_set(self, addr, header, fs):
        if hasattr(fs, 'IPV4_SRC_ADDR') and hasattr(fs, 'IPV4_DST_ADDR'):
            if fs.NAT_EVENT == 1:
                IPV4_SRC_ADDR = ipaddress.ip_address(fs.IPV4_SRC_ADDR)
                IPV4_DST_ADDR = ipaddress.ip_address(fs.IPV4_DST_ADDR)
                XLATE_SRC_ADDR_IPV4 = ipaddress.ip_address(fs.XLATE_SRC_ADDR_IPV4)

                self.buffer.append(
                    (int(fs.EVENT_TIME_MSEC/1000), IPV4_SRC_ADDR, IPV4_DST_ADDR, fs.L4_DST_PORT, XLATE_SRC_ADDR_IPV4, fs.XLATE_SRC_PORT, fs.PROTOCOL)
                )

                if len(self.buffer) >= self.buffer_size:
                    self.workers_pool.addRequest(self.buffer)
                    self.buffer = []

    def report_stats(self, seconds):
        logging.info('PgNelStoreProtocol: handled {0} flow sets in {1} datagrams for {2} seconds'.format(self._stat_flowsets, self._stat_dgrams, seconds))
        self._stat_dgrams = 0
        self._stat_flowsets = 0
        logging.info('PgNelStoreProtocol: queue size {0} current buffer {1}'.format(self.workers_pool.getQueueSize(), len(self.buffer)))


class MultiProtocol:
    class StatReporter(threading.Thread):
        def __init__(self, protocols):
            threading.Thread.__init__(self)
            self.protocols = protocols
            self.setDaemon(True)
            self.start()

        def run(self):
            while True:
                period = 60
                time.sleep(period)
                for proto in self.protocols:
                    proto.report_stats(period)

    def __init__(self, protocols):
        self._protocols = protocols
        self._stat_reporter = self.StatReporter(protocols)

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, buffer, addr):
        for proto in self._protocols:
            proto.datagram_received(buffer, addr)


@click.group(chain=True)
@click.option('-b', '--bind', default='127.0.0.1:9999', metavar='<host:port>', help='Listen interface.')
@click.pass_context
def multi(ctx, bind):
    pass


@multi.resultcallback()
def multi_process(protocols, bind):
    loglevel = getattr(logging, 'INFO')
    logging.basicConfig(
        level=loglevel,
        format='%(asctime)s %(name)s:%(levelname)s %(message)s',
    )

    loop = asyncio.get_event_loop()

    host, port = bind.split(':')
    port = int(port)
    listen = loop.create_datagram_endpoint(
        lambda: MultiProtocol(protocols),
        local_addr=(host, port))
    transport, protocol = loop.run_until_complete(listen)

    click.echo('Started %s' % bind)
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    transport.close()
    loop.close()


@multi.command()
@click.option('-h', '--host')
@click.option('-p', '--port', default='5432')
@click.option('-u', '--user', required=True)
@click.option('-w', '--password')
@click.option('-n', '--database', required=True)
@click.option('-t', '--threads', default=1)
def pg_nel_store(host, port, user, password, database, threads):
    dsn = {
        'database': database,
        'user': user,
        'password': password,
        'host': host,
        'port': port,
    }

    return PgNelStoreProtocol(dsn, threads)


@multi.command()
@click.option('-t', '--to', required=True, metavar='<host:port>', help='Where re-send packets.')
def mirror(to):
    host, port = to.split(':')
    port = int(port)

    loop = asyncio.get_event_loop()
    connect = loop.create_datagram_endpoint(
        MirrorProtocol, remote_addr=(host, port))
    target_trans, target_proto = loop.run_until_complete(connect)

    return MirrorProtocol(target_proto)


@click.command()
@click.argument('input', type=click.File('rb'))
def parse_pcap(input):
    ipv4_header = util.structuple('ipv4_header', '!IIIII', 'field1 field2 field3 src_addr dst_addr')
    nf_parser = nf.Parser(version=9)

    counter = 0
    for link_type, micro_second, link_packet in pcap.get_parser(input).read_packet():
        # print(link_type, micro_second, len(link_packet))
        ip4 = ipv4_header(link_packet[14:14+20])
        udp_data = link_packet[14 + 20 + 8:]  # skip Ethernet (14), IP (20) and UDP (8)

        for pkt_header, fs in nf_parser.parse(udp_data, ip4.src_addr):
            if hasattr(fs, 'IPV4_SRC_ADDR') and hasattr(fs, 'IPV4_DST_ADDR'):
                if fs.NAT_EVENT == 1:
                    pass

        counter += 1
        print('pkts: {0}'.format(counter), end='\r')
